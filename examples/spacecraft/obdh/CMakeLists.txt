cmake_minimum_required(VERSION 3.16)
project(spacecraft_obdh C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(spacecraft_obdh STATIC
    src/main.c
    src/ccsds.c
    src/telemetry.c
    src/tc.c
    src/ringbuf.c
    src/crc.c
    src/payload.c
)

target_include_directories(spacecraft_obdh PRIVATE include)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(spacecraft_obdh PRIVATE -Wall -Wextra)
endif()
