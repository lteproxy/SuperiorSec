# SuperiorSec

![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-blue?logo=githubactions&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

SuperiorSec is a Linux security and privacy inspection CLI. It collects local system information, process and socket snapshots, checks selected hardening settings, and can compare files against a SHA-256 baseline. The normal inspection commands are read-only and run without root privileges.

## About this project

SuperiorSec is my biggest personal software project so far. I have put a lot of time and effort into shaping it, and working on it has taught me a great deal about C++, Linux systems programming, and security. It has been a major learning experience, and I plan to keep improving it. I used AI assistance while building the project, including its small Python report-validation tool; the application and its security functionality are centered on C++.

## Features

- System, kernel, memory, uptime, and root-filesystem snapshot
- Process snapshot with PID, parent PID, state, UID, and command line
- TCP and UDP socket inspection through Linux `/proc` tables
- Read-only checks for ASLR, kernel pointer and log exposure, ptrace scope, setuid core dumps, SSH config permissions, and visible firewall rules
- SHA-256 file integrity baseline creation and comparison
- Human-readable and JSON output, including a combined system report
- C++ core tests and a Python report-schema validation helper

Firewall findings depend on `nft` or `iptables` being installed and readable by the current user. The audit reports settings for review; it does not change them or claim to be a complete compliance assessment.

## Requirements

- Linux with `/proc` mounted
- C++20 compiler (GCC 11+ or Clang 14+)
- CMake 3.20+
- OpenSSL 3 development files
- Python 3 is only needed for the optional report validation helper

Arch Linux, Debian, and Ubuntu are supported targets. The CI workflow builds on Ubuntu and Debian. The application uses Linux interfaces and is not intended for macOS or Windows.

### Install build dependencies

Arch Linux:

```sh
sudo pacman -S --needed base-devel cmake openssl
```

Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev
```

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The executable is `build/superiorsec`. To install it under `/usr/local`, use `cmake --install build` with the appropriate system permissions.

## Usage

```sh
./build/superiorsec system
./build/superiorsec processes --limit 20
./build/superiorsec network --json
./build/superiorsec audit
./build/superiorsec report --json --output report.json
python3 tools/validate_report.py report.json
```

Create and check a baseline for a directory you own or can read:

```sh
./build/superiorsec integrity init --root ./config --baseline ./config.sha256
./build/superiorsec integrity check --root ./config --baseline ./config.sha256
```

Creating a baseline writes a file. If the selected baseline already exists, `init` stops; pass `--force` only when you intend to replace that baseline. A comparison exits with status 1 when it finds changed, missing, or new files, or cannot complete the scan.

Top-level `--help` lists the available commands, and the inspection commands accept `--json`. Reports can contain process command lines, local addresses, and other machine details; review them before sharing.

## Architecture

The C++20 executable is split into small core modules for system facts, processes, network sockets, security checks, integrity baselines, and report formatting. Linux state is read from `/proc`, `/etc/os-release`, sysctl files, and filesystem metadata. SHA-256 uses OpenSSL EVP. The CLI and core do not need elevated privileges for normal inspection.

```text
src/main.cpp          CLI and argument handling
src/system.cpp        host, kernel, memory, uptime, disk
src/processes.cpp     /proc process snapshot
src/network.cpp       /proc TCP/UDP socket tables
src/audit.cpp         read-only hardening and firewall checks
src/integrity.cpp     SHA-256 baseline and comparison
src/report.cpp        combined text and JSON reports
```

The current release is a local CLI with built-in modules. A dynamic third-party plugin loader and web dashboard are not implemented and are not advertised as available features.

## Repository layout

```text
include/superiorsec/  Public core interfaces
src/                  C++20 implementation and CLI
tests/                CTest core checks
tools/                Python report validator
docs/                 Security and contribution notes
.github/workflows/    Ubuntu and Debian CI
```

## Security and scope

SuperiorSec is intended for defensive inspection of systems you own or are authorized to assess. It does not attempt to exploit systems, collect credentials, monitor keystrokes, establish persistence, or modify firewall and kernel settings. Normal inspection does not require root. Some files may be unreadable to an unprivileged user, so results can be incomplete; run with elevated permissions only when you understand why a specific read requires them.

This tool is not a substitute for a full security review. Recommendations depend on distribution, workload, and threat model. See [docs/security-model.md](docs/security-model.md).

## Development status

SuperiorSec is an early work in progress. The commands documented above are implemented and covered by local tests; the project will continue to grow as I learn and validate additional features.

## License

MIT. See [LICENSE](LICENSE).
