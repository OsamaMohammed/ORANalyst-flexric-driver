cmake_minimum_required(VERSION 3.15)
project(flexric_fuzz_bridge C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -O2 -g)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# bridge_core static library — all implementation modules
add_library(bridge_core STATIC
  src/sctp_client.c
  src/fuzz_ports.c
  src/crasher.c
)
target_link_libraries(bridge_core PUBLIC sctp pthread)

# main executable
add_executable(flexric_fuzz_bridge src/main.c)
target_link_libraries(flexric_fuzz_bridge PRIVATE bridge_core)

# --- Tests ---
enable_testing()

add_executable(test_inject_read test/test_inject_read.c)
target_link_libraries(test_inject_read PRIVATE bridge_core)
add_test(NAME inject_read COMMAND test_inject_read)

add_executable(test_crasher test/test_crasher.c)
target_link_libraries(test_crasher PRIVATE bridge_core)
add_test(NAME crasher COMMAND test_crasher)

add_executable(test_feedback test/test_feedback.c)
target_link_libraries(test_feedback PRIVATE bridge_core)
add_test(NAME feedback COMMAND test_feedback)
