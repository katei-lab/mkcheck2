cmake_minimum_required(VERSION 3.5)
project(mkcheck2 C Swift)

add_subdirectory(Sources)

add_compile_options($<$<COMPILE_LANGUAGE:Swift>:-index-store-path ${CMAKE_BINARY_DIR}/IndexStore/index>)
