cmake_minimum_required(VERSION 2.9)

project(MilterFrom C)

set(CMAKE_CXX_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

find_package(Threads REQUIRED)
find_package(Milter REQUIRED)

include_directories(${Milter_INCLUDE_DIRS})
add_executable(milterfrom milterfrom.c)
target_link_libraries(milterfrom ${Milter_LIBRARY})
