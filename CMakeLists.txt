cmake_minimum_required(VERSION 3.0.0)
project(ptrace_monitor VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(ptrace_monitor monitor.c)
target_link_libraries(ptrace_monitor unwind)
target_link_libraries(ptrace_monitor unwind-ptrace unwind-generic)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
