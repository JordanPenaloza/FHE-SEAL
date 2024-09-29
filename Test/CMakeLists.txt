cmake_minimum_required(VERSION 3.10)
project(test_program)

# Find SEAL package
find_package(SEAL REQUIRED)

# Add your executable
add_executable(test test.cpp)

# Link SEAL library
target_link_libraries(test SEAL::seal)
