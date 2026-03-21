# ©AngelaMos | 2026
# CMakeLists.txt

cmake_minimum_required(VERSION 3.25...4.2)

project(
    hashcracker
    VERSION 1.0.0
    DESCRIPTION "Multi-threaded hash cracking tool"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(project_warnings INTERFACE)
target_compile_options(project_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion
    -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    -Woverloaded-virtual -Wsign-conversion
)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options)

set(HASHCRACKER_SOURCES
    src/hash/MD5Hasher.cpp
    src/hash/SHA1Hasher.cpp
    src/hash/SHA256Hasher.cpp
    src/hash/SHA512Hasher.cpp
    src/hash/HashDetector.cpp
    src/attack/DictionaryAttack.cpp
    src/attack/BruteForceAttack.cpp
    src/attack/RuleAttack.cpp
    src/rules/RuleSet.cpp
    src/threading/ThreadPool.cpp
    src/display/Progress.cpp
)

add_library(hashcracker_lib STATIC ${HASHCRACKER_SOURCES})
target_include_directories(hashcracker_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hashcracker_lib
    PUBLIC OpenSSL::Crypto project_warnings
)
target_compile_features(hashcracker_lib PUBLIC cxx_std_23)

add_executable(hashcracker main.cpp)
target_link_libraries(hashcracker
    PRIVATE hashcracker_lib Boost::program_options project_warnings
)

include(FetchContent)
FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW TRUE
    SYSTEM
)
FetchContent_MakeAvailable(googletest)
enable_testing()

set(HASHCRACKER_TESTS
    tests/test_hashers.cpp
    tests/test_hash_detector.cpp
    tests/test_dictionary_attack.cpp
    tests/test_bruteforce_attack.cpp
    tests/test_rules.cpp
    tests/test_engine.cpp
)

add_executable(hashcracker_tests ${HASHCRACKER_TESTS})
target_link_libraries(hashcracker_tests
    PRIVATE hashcracker_lib GTest::gtest_main
)
include(GoogleTest)
gtest_discover_tests(hashcracker_tests)
