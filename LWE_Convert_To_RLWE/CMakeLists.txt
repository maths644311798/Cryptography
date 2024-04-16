
cmake_minimum_required(VERSION 3.10)

project(test VERSION 1.0 LANGUAGES CXX)
project(test1 VERSION 1.0 LANGUAGES CXX)

set(CMAKE_BUILD_TYPE Debug)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

add_executable(test test.cpp lweCipherText.cpp)
add_executable(test1 test1.cpp lweCipherText.cpp utils.cc)
# Import Microsoft SEAL
find_package(SEAL 4.1 REQUIRED)

# Link Microsoft SEAL
target_link_libraries(test SEAL::seal)
target_link_libraries(test1 SEAL::seal)
