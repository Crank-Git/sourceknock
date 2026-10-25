# sourceknock - Makefile
#
#   make            build the daemon (Linux) + all tests
#   make test       build and run the cross-platform unit tests (macOS/Linux)
#   make daemon     build the sourceknock daemon (requires Linux headers)
#   make fuzz       build + run the libFuzzer pkt_parse target (Linux, needs
#                   clang with libFuzzer + AddressSanitizer)
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?=

OS := $(shell uname -s)

# On macOS the default CommandLineTools SDK (27.x) ships a libSystem.B.tbd
# that references arm64e.x1, which this linker can't parse. Pick an older SDK
# whose tbd does NOT list that architecture and pass it via -isysroot.
ifeq ($(OS),Darwin)
  FOUND_SDK := $(shell for s in \
    /Library/Developer/CommandLineTools/SDKs/MacOSX15.2.sdk \
    /Library/Developer/CommandLineTools/SDKs/MacOSX14.4.sdk \
    /Library/Developer/CommandLineTools/SDKs/MacOSX13.3.sdk \
    /Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk ; do \
    if [ -f "$$s/usr/lib/libSystem.B.tbd" ] && \
       ! grep -q 'arm64e.x1' "$$s/usr/lib/libSystem.B.tbd"; then echo "$$s"; break; fi; \
  done )
  ifneq ($(FOUND_SDK),)
    CFLAGS += -isysroot $(FOUND_SDK)
    LDFLAGS += -isysroot $(FOUND_SDK)
  endif
endif

SRC     := src/state.c src/packet.c src/config.c src/close.c
CORE_OBJ:= $(SRC:.c=.o)

# Daemon links Linux-only capture/reward layers.
DAEMON_SRC := src/sourceknock.c src/capture.c src/reward.c $(SRC)
DAEMON_OBJ := $(DAEMON_SRC:.c=.o)

TESTS := state_test packet_test config_test close_test

# ---- fuzzing (Linux only: needs libFuzzer + ASan) ----
FUZZ_DIR     := tests/fuzz
FUZZ_SRC     := $(FUZZ_DIR)/fuzz_pkt_parse.cc
FUZZ_BIN     := $(FUZZ_DIR)/fuzz_pkt_parse
FUZZ_CORPUS  := $(FUZZ_DIR)/corpus/pkt_parse
FUZZ_CXXFLAGS := -O2 -g -std=c++14 -fsanitize=fuzzer,address -Isrc
# libFuzzer is a clang feature; gcc lacks the runtime.
FUZZ_CC ?= clang

.PHONY: all test daemon fuzz fuzz-build fuzz-seeds clean format check-format tidy

all: test

# ---- code quality (clang-format + clang-tidy) ----
# Requires a real clang-format / clang-tidy (apt install clang, or
# `brew install clang-format` on macOS). The pip `clang-format` wrapper does
# NOT support `--check`, so use a packaged binary for `make check-format`.
FORMAT_FILES := $(wildcard src/*.c src/*.h tests/*.c tests/*.h tests/fuzz/*.c tests/fuzz/*.cc)
# make_seeds.py generates the fuzz corpus; it is Python, not C, so it is
# intentionally excluded from the clang-format check above.

format:
	clang-format -i $(FORMAT_FILES)

check-format:
	@ok=0; \
	for f in $(FORMAT_FILES); do \
		if ! clang-format "$$f" 2>/dev/null | diff -q "$$f" - >/dev/null 2>&1; then \
			echo "NOT FORMATTED: $$f"; ok=1; \
		fi; \
	done; \
	if [ $$ok -ne 0 ]; then echo "Run 'make format' to fix."; exit 1; fi; \
	echo "All files clang-format clean"

tidy:
	clang-tidy $(DAEMON_SRC) -- -Isrc -std=gnu11

# ---- unit tests (pure core, runs anywhere with a C compiler) ----
test: $(TESTS)
	@echo "=== running test suites ==="
	@rc=0; for t in $(TESTS); do ./$$t || rc=1; done; \
	 if [ $$rc -eq 0 ]; then echo "ALL GREEN"; else echo "FAILURES ABOVE"; fi; \
	 exit $$rc

%_test.o: tests/%_test.c
	$(CC) $(CFLAGS) -Isrc -Itests -c $< -o $@

# each test links against the pure core
state_test: tests/state_test.o src/state.o
	$(CC) $^ -o $@ $(LDFLAGS)
packet_test: tests/packet_test.o src/packet.o
	$(CC) $^ -o $@ $(LDFLAGS)
config_test: tests/config_test.o src/config.o
	$(CC) $^ -o $@ $(LDFLAGS)
close_test: tests/close_test.o src/close.o
	$(CC) $^ -o $@ $(LDFLAGS)

# ---- fuzzing (Linux only) ----
# Compile the C++ target and the C parser separately (the C++ std flag is
# invalid for the C file), then link with the libFuzzer runtime. Fails
# (non-zero) if the fuzzer finds a crash.
fuzz-build:
	$(FUZZ_CC) -O2 -g -std=c++14 -fsanitize=fuzzer,address \
		-c $(FUZZ_SRC) -Isrc -o $(FUZZ_DIR)/fuzz_pkt_parse.o
	$(FUZZ_CC) -O2 -g -fsanitize=address \
		-c src/packet.c -Isrc -o $(FUZZ_DIR)/packet.fuzz.o
	$(FUZZ_CC) -fsanitize=fuzzer,address \
		$(FUZZ_DIR)/fuzz_pkt_parse.o $(FUZZ_DIR)/packet.fuzz.o -o $(FUZZ_BIN)

fuzz: fuzz-build
	$(FUZZ_BIN) -max_total_time=60 -timeout=10 $(FUZZ_CORPUS)

# Regenerate the seed corpus on any host (no libFuzzer needed).
fuzz-seeds:
	python3 $(FUZZ_DIR)/make_seeds.py

# ---- the daemon (Linux only) ----
daemon: sourceknock
sourceknock: $(DAEMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -Isrc -c $< -o $@

clean:
	rm -f $(CORE_OBJ) $(DAEMON_OBJ) $(TESTS) sourceknock tests/*.o $(FUZZ_BIN) $(FUZZ_DIR)/*.o
