cmake_minimum_required(VERSION 3.20)
project(SuperiorSec VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_library(superiorsec_core
    src/audit.cpp
    src/common.cpp
    src/integrity.cpp
    src/network.cpp
    src/processes.cpp
    src/report.cpp
    src/system.cpp
)
target_include_directories(superiorsec_core PUBLIC include)
target_compile_features(superiorsec_core PUBLIC cxx_std_20)
target_link_libraries(superiorsec_core PUBLIC OpenSSL::Crypto)
target_compile_options(superiorsec_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

add_executable(superiorsec src/main.cpp)
target_link_libraries(superiorsec PRIVATE superiorsec_core)
target_compile_options(superiorsec PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)

if(BUILD_TESTING)
    add_executable(superiorsec_tests tests/core_tests.cpp)
    target_link_libraries(superiorsec_tests PRIVATE superiorsec_core)
    target_compile_options(superiorsec_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    add_test(NAME superiorsec_core COMMAND superiorsec_tests)
endif()

install(TARGETS superiorsec RUNTIME DESTINATION bin)
