cmake_minimum_required(VERSION 3.20)

project(officer VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

add_executable(officer-agent
    src/main.cpp
)

target_compile_features(officer-agent PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(officer-agent PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()

add_subdirectory(tools/query)
