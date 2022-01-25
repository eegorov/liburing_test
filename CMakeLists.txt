cmake_minimum_required(VERSION 3.15)
project(liburing_test C)

set(CMAKE_C_STANDARD 99)

add_executable(liburing_test liburing_test.c)
target_link_libraries(liburing_test uring)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_and_check.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/cleanup.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
