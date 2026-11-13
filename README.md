# SuperiorSec

![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-blue?logo=githubactions&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

SuperiorSec is a linux security and privacy inspection CLI. it collects local system information, process and socket snapshots, checks selected hardening settings, and can compare files against a SHA-256 baseline.
The normal inspection commands are read-only and run without root perms

## about

SuperiorSec is my biggest personal project so far. i have put a lot of time and effort into it, and working on it has taught me a great deal about c++, programming, and security. it has been a major learning experience, and i plan to keep improving it.
the application and its security functionality are centered on c++

## features

- system, kernel, memory, uptime, and root filesystem snapshot
- process snapshot with PID, parent PID, state, UID, and command line
- TCP and UDP socket inspection through Linux `/proc` tables
- read-only checks for ASLR, kernel pointer and log exposure, ptrace scope, setuid core dumps, SSH config permissions, and visible firewall rules
- SHA-256 file integrity baseline creation and comparison
- human-readable and JSON output, including a combined system report
- c++ core tests and a Python report validation helper

firewall findings depend on `nft` or `iptables` being installed and readable by the current user

## requirements

- linux with `/proc` mounted
- c++20 compiler (GCC 11+ or Clang 14+)
- CMake 3.20+
- OpenSSL 3 development files
- python 3 is only needed for the optional report validation helper

arch linux, debian, and ubuntu are supported targets. The CI workflow builds on ubuntu and debian.
the application uses Linux interfaces and is not intended for macOS or Windows.

### install build dependencies

arch:

```sh
sudo pacman -S --needed base-devel cmake openssl
```

debian or ubuntu:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev
```

## build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

the executable is `build/superiorsec`. to install it under `/usr/local`, use `cmake --install build` with the appropriate system permissions

## yusage

```sh
./build/superiorsec system
./build/superiorsec processes --limit 20
./build/superiorsec network --json
./build/superiorsec audit
./build/superiorsec report --json --output report.json
python3 tools/validate_report.py report.json
```

create and check a baseline for a directory you own or can read:

```sh
./build/superiorsec integrity init --root ./config --baseline ./config.sha256
./build/superiorsec integrity check --root ./config --baseline ./config.sha256
```

creating a baseline writes a file. If the selected baseline already exists, `init` stops; pass `--force` only when you intend to replace that baseline. a comparison exits with status 1 when it finds changed, missing, or new files, or cannot complete the scan.

top level `--help` lists the available commands, and the inspection commands accept `--json`. reports can contain process command lines, local addresses, and other machine details

## architecture

The C++20 executable is split into small core modules for system facts, processes, network sockets, security checks, integrity baselines, and report formatting. linux state is read from `/proc`, `/etc/os-release`, sysctl files, and filesystem metadata. SHA-256 uses OpenSSL EVP

```text
src/main.cpp          CLI and argument handling
src/system.cpp        host, kernel, memory, uptime, disk
src/processes.cpp     /proc process snapshot
src/network.cpp       /proc TCP/UDP socket tables
src/audit.cpp         read-only hardening and firewall checks
src/integrity.cpp     SHA-256 baseline and comparison
src/report.cpp        combined text and JSON reports
```

the current release is a local CLI with built in modules

## repository layout

```text
include/superiorsec/  Public core interfaces
src/                  C++20 implementation and CLI
tests/                CTest core checks
tools/                Python report validator
docs/                 Security and contribution notes
.github/workflows/    Ubuntu and Debian CI
```

## license

MIT. See [LICENSE](LICENSE).
