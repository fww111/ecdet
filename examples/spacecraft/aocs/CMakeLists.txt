cmake_minimum_required(VERSION 3.16)
project(spacecraft_aocs C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(spacecraft_aocs STATIC
    src/main.c
    src/imu.c
    src/attitude.c
    src/wheel.c
    src/orbit.c
    src/fdir.c
)

target_include_directories(spacecraft_aocs PRIVATE include)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(spacecraft_aocs PRIVATE -Wall -Wextra)
endif()
