cmake_minimum_required(VERSION 3.16)
project(spacecraft_eps C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(spacecraft_eps STATIC
    src/main.c
    src/mppt.c
    src/battery.c
    src/heater.c
    src/adc_isr.c
    src/protection.c
)

target_include_directories(spacecraft_eps PRIVATE include)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(spacecraft_eps PRIVATE -Wall -Wextra)
endif()
