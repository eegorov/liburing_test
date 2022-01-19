cmake_minimum_required(VERSION 3.15)
project(liburing_test C)

set(CMAKE_C_STANDARD 99)

add_executable(liburing_test liburing_test.c)
target_link_libraries(liburing_test uring)
