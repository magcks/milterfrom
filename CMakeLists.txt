cmake_minimum_required(VERSION 3.0)

project(MilterFrom C)

option(WITH_SYSTEMD "Install Systemd unit files" ON)
set(SYSTEMD_UNITDIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system" CACHE PATH "Systemd unit directory")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(Milter REQUIRED)

add_executable(milterfrom src/milterfrom.c)
target_include_directories(milterfrom PRIVATE ${Milter_INCLUDE_DIRS})
target_link_libraries(milterfrom ${Milter_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS milterfrom DESTINATION bin)
if(NOT WIN32 AND WITH_SYSTEMD)
	configure_file(systemd/milterfrom.service.in ${CMAKE_CURRENT_BINARY_DIR}/systemd/milterfrom.service)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/milterfrom.service DESTINATION ${SYSTEMD_UNITDIR})
endif()