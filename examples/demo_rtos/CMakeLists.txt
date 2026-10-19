cmake_minimum_required(VERSION 3.16)
project(demo_rtos C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(demo_rtos
    src/main.c
    src/sensor.c
    src/comm.c
)
