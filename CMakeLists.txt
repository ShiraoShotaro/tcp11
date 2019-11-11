##################################################
## CMakeLists for tcp11
##
## (c) 2019 Shirao Shotaro
## Released under the MIT license (ref. LICENSE)
##################################################

cmake_minimum_required(VERSION 3.8)
project(tcp11)

### Project Settings
if(UNIX) # for Linux
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

elseif(WIN32) # for Windows
    set(CMAKE_CXX_FLAGS_RELEASE "/MT")
    
    # Source code are treated as UTF-8 (Must to use UTF-8 BOM)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /source-charset:utf-8")

endif(UNIX)

# Source Files
add_library(tcp11 src/tcp11.cpp src/tcp11.hpp)
