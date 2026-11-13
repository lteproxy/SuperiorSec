# Contributing

Keep security checks read-only unless a separately reviewed feature has a clear, explicit user action. Do not add shell execution built from user-supplied strings, collect secrets, or claim coverage that the implementation does not provide.

Use the existing CMake build and CTest suite:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/superiorsec report --json | python3 tools/validate_report.py
```

New modules should have focused tests and document Linux interfaces, permission requirements, and known limits. Keep optional tooling small and avoid adding runtime dependencies without a concrete need.
