# sourceknock - Makefile
#
#   make            build the daemon (Linux) + all tests
#   make test       build and run the cross-platform unit tests (macOS/Linux)
#   make daemon     build the sourceknock daemon (requires Linux headers)
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

.PHONY: all test daemon clean

all: test

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

# ---- the daemon (Linux only) ----
daemon: sourceknock
sourceknock: $(DAEMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -Isrc -c $< -o $@

clean:
	rm -f $(CORE_OBJ) $(DAEMON_OBJ) $(TESTS) sourceknock tests/*.o
