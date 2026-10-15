# =============================================================================
# FILE: CMakeLists.txt  (build instructions)
# WHAT   Tells CMake how to build three things from the same code:
#          phishguard_core   a library with ALL the logic (everything in src/ except main.cpp)
#          phishguard        the program users run (main.cpp + the library)
#          phishguard_tests  the automated tests (tests/*.cpp + the library)
# WHY    Splitting a library from main() lets the tests call the real code directly.
# OPTIONS  -DPG_SANITIZE=ON adds AddressSanitizer + UBSan (finds memory bugs; Linux/WSL/clang).
#          Release is the default build type. PG_DATA_DIR is baked into the tests so they find data/
#          wherever they are started from. New .cpp files are picked up automatically (GLOB).
# =============================================================================

cmake_minimum_required(VERSION 3.16)
project(PhishGuard VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(PG_SANITIZE "Build with AddressSanitizer + UBSan (Linux/WSL/clang)" OFF)

# Core library: everything except main(), so tests can link against it.
file(GLOB_RECURSE PG_CORE_SOURCES CONFIGURE_DEPENDS src/*.cpp)
list(FILTER PG_CORE_SOURCES EXCLUDE REGEX ".*/src/main\\.cpp$")
add_library(phishguard_core ${PG_CORE_SOURCES})
target_include_directories(phishguard_core PUBLIC include)

if(MSVC)
    target_compile_options(phishguard_core PUBLIC /W4 /utf-8)
else()
    target_compile_options(phishguard_core PUBLIC -Wall -Wextra -Wpedantic)
endif()
if(PG_SANITIZE AND NOT MSVC)
    target_compile_options(phishguard_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(phishguard_core PUBLIC -fsanitize=address,undefined)
endif()

add_executable(phishguard src/main.cpp)
target_link_libraries(phishguard PRIVATE phishguard_core)

enable_testing()
file(GLOB PG_TEST_SOURCES CONFIGURE_DEPENDS tests/*.cpp)
add_executable(phishguard_tests ${PG_TEST_SOURCES})
target_link_libraries(phishguard_tests PRIVATE phishguard_core)
target_compile_definitions(phishguard_tests PRIVATE PG_DATA_DIR="${CMAKE_SOURCE_DIR}/data")
add_test(NAME all_tests COMMAND phishguard_tests)
