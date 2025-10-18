cmake_minimum_required(VERSION 3.16)
project(wirecut VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(WIRECUT_SANITIZE "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(WIRECUT_FUZZER "Build libFuzzer harness (Clang required)" OFF)
option(WIRECUT_COVERAGE "Enable code coverage instrumentation" OFF)

if(WIRECUT_FUZZER)
    set(WIRECUT_SANITIZE ON)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(wirecut STATIC src/parser.cpp)
target_include_directories(wirecut PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(wirecut PUBLIC cxx_std_17)

add_executable(wirecut-parse src/cli.cpp)
target_link_libraries(wirecut-parse PRIVATE wirecut)

add_executable(wirecut-tests tests/test_parser.cpp)
target_link_libraries(wirecut-tests PRIVATE wirecut)

if(WIRECUT_FUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "WIRECUT_FUZZER requires Clang (libFuzzer)")
    endif()
    add_executable(wirecut-fuzz fuzz/fuzz_parser.cpp)
    target_link_libraries(wirecut-fuzz PRIVATE wirecut)
    target_compile_options(wirecut-fuzz PRIVATE -fsanitize=fuzzer)
    target_link_options(wirecut-fuzz PRIVATE -fsanitize=fuzzer)
endif()

if(WIRECUT_SANITIZE)
    set(WIRECUT_SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(wirecut PUBLIC ${WIRECUT_SAN_FLAGS})
    target_link_options(wirecut PUBLIC ${WIRECUT_SAN_FLAGS})
endif()

if(WIRECUT_COVERAGE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(WIRECUT_COV_FLAGS -fprofile-instr-generate -fcoverage-mapping)
    else()
        set(WIRECUT_COV_FLAGS --coverage)
    endif()
    target_compile_options(wirecut PUBLIC ${WIRECUT_COV_FLAGS})
    target_link_options(wirecut PUBLIC ${WIRECUT_COV_FLAGS})
endif()

enable_testing()
add_test(NAME parser_unit COMMAND wirecut-tests)
