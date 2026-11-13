# contributing

keep security checks read only unless a feature has a clear user action. do not build shell commands from user input. do not collect secrets. do not claim checks the code does not perform.

run the build and tests with these commands.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/superiorsec report --json | python3 tests/validate_report.py
```

new modules should have focused tests. explain which Linux interfaces they use and note permission needs and known limits. keep helper tools small. add a runtime dependency only when the project needs it.
