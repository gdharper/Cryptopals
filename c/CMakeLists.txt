
cmake_minimum_required(VERSION 3.12)

project(CryptopalsC
    VERSION 0.1.0
    DESCRIPTION "An implemetation of the Cryptopals challenges in C"
    LANGUAGES C)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()

add_subdirectory(app)
add_subdirectory(codec)

if( (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME) AND BUILD_TESTING)
    add_subdirectory(test)
endif()

