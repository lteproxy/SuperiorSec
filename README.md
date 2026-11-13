# superiorsec

[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)](https://en.cppreference.com/w/cpp/20) [![CI](https://github.com/lteproxy/SuperiorSec/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/lteproxy/SuperiorSec/actions/workflows/ci.yml) [![MIT license](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/lteproxy/SuperiorSec/blob/main/LICENSE)

SuperiorSec is a Linux security and privacy inspection CLI. it collects local system information and checks selected security settings. it also snapshots processes and network sockets and compares files with a SHA-256 baseline. the inspection commands only read system data and run without root.

## about this project

this is my biggest personal project so far. i have put a lot of time into building it and learning along the way. it has taught me about C++ and Linux systems programming and security. i used AI assistance while building the project and made a small Python tool to check reports. the main application is written in C++. it is still a work in progress and i plan to keep improving it.

## what it does

- shows the system and kernel version.
- shows available memory and space on the root disk. it also shows uptime.
- lists each process with its PID and parent PID. it also shows the UID and state and command line.
- shows TCP and UDP sockets from Linux `/proc` files.
- checks a few settings such as ASLR and ptrace scope. it also checks kernel pointer exposure.
- checks SSH configuration permissions and looks for visible firewall rules.
- creates and checks SHA-256 file baselines.
- writes plain text or JSON reports.

the firewall check can show unknown if `nft` or `iptables` is missing or the rules cannot be read. it never changes firewall or kernel settings.

## what you need

- Linux with `/proc` mounted.
- a C++20 compiler such as GCC 11 or Clang 14.
- CMake 3.20 or newer.
- OpenSSL 3 development files.
- Python 3 for the optional report checker.

i develop on Arch Linux. CI also builds on Ubuntu and Debian. the program uses Linux interfaces and does not run on macOS or Windows.

## install the build tools

on Arch Linux run this command.

```sh
sudo pacman -S --needed base-devel cmake openssl
```

on Debian or Ubuntu run these commands.

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

the program builds to `build/superiorsec`. you can install it under `/usr/local` with `cmake --install build`. this may need system permissions.

## try it

```sh
./build/superiorsec system
./build/superiorsec processes --limit 20
./build/superiorsec network --json
./build/superiorsec audit
./build/superiorsec report --json --output report.json
python3 tests/validate_report.py report.json
```

create and check a baseline for a directory you can read.

```sh
./build/superiorsec integrity init --root ./config --baseline ./config.sha256
./build/superiorsec integrity check --root ./config --baseline ./config.sha256
```

creating a baseline writes a file. `init` stops if the baseline already exists. use `--force` only when you want to replace it. `check` returns status 1 if files have changed or are missing or new. it also returns 1 if the scan cannot finish.

run `--help` to see the available commands. inspection commands accept `--json`. reports can include process command lines and local addresses. check a report before sharing it.

## how it works

the program is written in C++20. it reads system details and process information. it also shows network sockets and checks a few security settings. it can compare files with a baseline and put the results into a report.

it reads Linux data from `/proc` and `/etc/os-release` and from sysctl files and filesystem metadata. OpenSSL EVP handles SHA-256 hashing. normal inspection does not need root.

```text
src/main.cpp          CLI and argument handling
src/system.cpp        system and kernel details
src/processes.cpp     process snapshot
src/network.cpp       TCP and UDP socket tables
src/audit.cpp         security and firewall checks
src/integrity.cpp     SHA-256 baseline and comparison
src/report.cpp        text and JSON reports
```

the current version is a local CLI with built in modules. a plugin loader and web dashboard are not included yet.

## project files

```text
include/superiorsec/  C++ interfaces
src/                  C++ implementation and CLI
tests/                CTest checks and Python report checker
docs/                 security and contribution notes
.github/workflows/    GitHub Actions CI
```

## security notes

use SuperiorSec only on systems you own or have permission to inspect. it does not exploit systems or collect credentials. it does not monitor keystrokes or add persistence. it does not change firewall rules or kernel settings. some files may need extra permissions to read. this can leave gaps in the results. use elevated permissions only when a specific read needs them.

the checks cover a few settings. they are not a full security review. what to do with a result depends on your system and what you want to protect. see `docs/security-model.md`.

## where things stand

SuperiorSec is still a work in progress. the commands in this guide are implemented and covered by tests. i plan to keep improving the project as i learn more.

## license

the project uses the MIT license. see `LICENSE`.
