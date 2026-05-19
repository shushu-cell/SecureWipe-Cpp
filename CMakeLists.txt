cmake_minimum_required(VERSION 3.21)

project(SecureWipeCpp VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(securewipe_lib STATIC
	src/secure_wipe.cpp
	src/secure_wipe_engine.cpp
)

target_include_directories(securewipe_lib
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(securewipe_lib PUBLIC cxx_std_17)

if(MSVC)
	target_compile_options(securewipe_lib PRIVATE /W4 /permissive-)
else()
	target_compile_options(securewipe_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(securewipe
	src/cli_application.cpp
	src/main.cpp
)

target_link_libraries(securewipe PRIVATE securewipe_lib)

if(MSVC)
	target_compile_options(securewipe PRIVATE /W4 /permissive-)
else()
	target_compile_options(securewipe PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(securewipe PROPERTIES
	OUTPUT_NAME securewipe
)

install(TARGETS securewipe securewipe_lib
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES
	include/secure_wipe.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(BUILD_TESTING AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt)
	add_subdirectory(tests)
endif()
