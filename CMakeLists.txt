cmake_minimum_required(VERSION 3.0)

project(MilterFrom C)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(Milter REQUIRED)

add_executable(milterfrom src/milterfrom.c)
target_include_directories(milterfrom PRIVATE ${Milter_INCLUDE_DIRS})
target_link_libraries(milterfrom ${Milter_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})