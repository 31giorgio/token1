cmake_minimum_required(VERSION 3.10)
project(lab3 C)

add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(SHARED_DEF_GEN_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_shared_defs.py)
add_custom_target(generate_shared_defs ALL
	COMMAND ${Python3_EXECUTABLE} ${SHARED_DEF_GEN_SCRIPT} ${CMAKE_CURRENT_SOURCE_DIR}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	COMMENT "Generating shared C/Python command and error definitions"
)

set(PROJECT_HEADERS
	include/command.h
	include/debug.h
	include/error.h
	include/exports.h
	include/generated_commands.h
	include/generated_errors.h
	include/network.h
	include/protocol.h
	include/security.h
)

set(PROJECT_SOURCES
	src/command.c
	src/debug.c
	src/exports.c
	src/network.c
	src/protocol.c
	src/security.c
)

add_library(lab3 SHARED ${PROJECT_SOURCES} ${PROJECT_HEADERS})
add_dependencies(lab3 generate_shared_defs)

target_include_directories(lab3 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(lab3 advapi32 kernel32 ws2_32)

target_compile_options(lab3 PRIVATE /W4 /WX)

add_executable(lab3_host host/lab3_host.c)

target_include_directories(lab3_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(lab3_host kernel32)

target_compile_options(lab3_host PRIVATE /W4 /WX)
