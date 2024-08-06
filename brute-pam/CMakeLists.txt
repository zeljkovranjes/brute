cmake_minimum_required(VERSION 3.22)
project(pam C)

set(CMAKE_C_STANDARD 11)

# Find the required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)

# Include directories
include_directories(${CURL_INCLUDE_DIRS})

# Set the output directory for the shared library
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Add the shared library
add_library(pam_module SHARED library.c)

# Link libraries
target_link_libraries(pam_module ${CURL_LIBRARIES})

# Install the shared library
install(TARGETS pam_module LIBRARY DESTINATION /lib/security)


# original
#cmake_minimum_required(VERSION 3.29)
#project(pam C)

#set(CMAKE_C_STANDARD 11)

#include_directories(.)

#add_executable(pam
#        library.c
#        library.h)
