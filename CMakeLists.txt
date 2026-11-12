cmake_minimum_required(VERSION 3.16)
project(gcm_forbidden CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()
add_compile_options(-O2 -Wall -Wextra)

find_package(OpenSSL REQUIRED)

# Core library: field + GCM are fully implemented; poly/attack/victim are stubs.
add_library(gcmcore
        gf128.cpp
        gcm.cpp
        gf128poly.cpp
        attack.cpp
        victim.cpp)
target_link_libraries(gcmcore PUBLIC OpenSSL::Crypto)

# GATE #1 — the test harness. `ctest` or run ./tests directly.
add_executable(tests tests.cpp)
target_link_libraries(tests PRIVATE gcmcore)

# Live demo driver (fill in main.cpp as the attack comes together).
add_executable(forbidden main.cpp)
target_link_libraries(forbidden PRIVATE gcmcore)

# GATE #3 — polynomial / root-finding unit tests. `./poly_tests [name-filter]`
add_executable(poly_tests poly_tests.cpp)
target_link_libraries(poly_tests PRIVATE gcmcore)

enable_testing()
add_test(NAME gate1 COMMAND tests)
add_test(NAME gate3 COMMAND poly_tests)
