cmake_minimum_required(VERSION 3.16)
project(spacecraft_ttc C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(spacecraft_ttc STATIC
    src/main.c
    src/tc_decode.c
    src/fec.c
    src/ranging.c
    src/auth.c
    src/dma.c
)

target_include_directories(spacecraft_ttc PRIVATE include)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(spacecraft_ttc PRIVATE -Wall -Wextra)
endif()
