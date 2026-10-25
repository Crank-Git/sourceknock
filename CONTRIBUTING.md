# Contributing to sourceknock

Thanks for caring about this project. This guide covers building, testing,
formatting, fuzzing, and the branch/PR workflow. For the threat model,
configuration reference, and running/operating instructions, see the
[README](README.md).

## Requirements

- A C11 compiler (`cc`/`gcc`/`clang`).
- For the daemon and the Linux-only layers: Linux with kernel headers, plus
  `AF_PACKET` and nftables access (root, or `CAP_NET_RAW` + `CAP_NET_ADMIN`).
- For formatting: a real **clang-format 17.0.6**. The pip `clang-format`
  wrapper does **not** support `--check`, so CI installs a pinned binary in a
  venv. To match locally:

  ```sh
  python3 -m venv /tmp/cf_venv
  /tmp/cf_venv/bin/pip install "clang-format==17.0.6"
  export PATH="/tmp/cf_venv/bin:$PATH"
  ```

## Build

```sh
make            # build the daemon (Linux) + all unit tests
make daemon     # build just the sourceknock daemon (Linux only)
```

On macOS the Makefile auto-selects an older Xcode SDK whose
`libSystem.B.tbd` does not reference `arm64e.x1`, and passes it via
`-isysroot`. If your default SDK fails to link, the Makefile falls back to a
known-good one.

## Test

```sh
make test       # build + run the cross-platform unit tests
```

This runs `state_test`, `packet_test`, `config_test`, and `close_test` against
the pure core (no socket code), so it works on any OS with a C compiler.

### Integration (e2e) test — Linux + root only

`tests/e2e_integration.sh` drives a full knock cycle inside a Linux network
namespace over a real veth capture interface and real nftables: it knocks,
asserts the service port opens, then asserts it closes again (on the fixed TTL
or on first connect). It exits non-zero if any expectation is wrong.

```sh
# on a Linux host with sudo:
sudo bash tests/e2e_integration.sh tests/e2e_fixed.conf
sudo bash tests/e2e_integration.sh tests/e2e_close.conf
```

The harness runs hermetically in a private temp dir, so it needs no
pre-existing scratch directory. It requires the daemon to be built at
`./sourceknock` first (`make daemon`).

## Formatting & lint

```sh
make format     # reformat src/ and tests/ with clang-format
make check-format   # fail if anything is not clang-format clean
make tidy       # clang-tidy (non-blocking in CI)
```

`make check-format` must pass on every PR. Use the pinned clang-format 17.0.6
(see above) so your output matches CI. The code style is Allman braces.

## Fuzzing

The packet parser (`src/packet.c`) is the fuzz target, because it decodes
untrusted, variable-length Ethernet/IPv4/IPv6 frames.

```sh
make fuzz-seeds # regenerate the seed corpus (Python, any host)
make fuzz       # build + run the libFuzzer target with ASan (Linux, clang)
```

`make fuzz` needs clang with libFuzzer and AddressSanitizer; it fails (non-zero)
if it finds a crash. The CI fuzz run is a bounded, Linux-only job.

## Branch & PR workflow

- **One issue = one feature branch + one PR.** Create the branch from
  `dev` (the integration branch), never from `main`:

  ```sh
  git checkout -b feature/your-issue origin/dev
  ```

- Keep `dev` and `main` protected; **never push to `dev` or `main` directly.**
- Open a PR against `dev`. Each PR should be small and self-contained, with a
  commit message that references the issue (e.g. `... (issue #18)`).
- CI runs on every push and PR: unit tests on Linux and macOS, the daemon
  build and e2e test on Linux, plus clang-format, clang-tidy, and a secrets
  scan. All must be green before merge.

## What to test before you push

1. `make test` is green.
2. `make check-format` reports "All files clang-format clean".
3. If you touched the daemon or the parser, run the e2e test on Linux (see
   above) and, ideally, `make fuzz` for a bounded run.

## Adding a config example

If you add a sample under `examples/`, make sure it parses: the daemon loads it
at startup (`config_parse_file`), and `make test`'s `config_test` exercises the
parser. A malformed example will fail the daemon's own startup check.
