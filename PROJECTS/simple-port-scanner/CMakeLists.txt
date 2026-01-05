cmake_minimum_required(VERSION 3.31)
project(simplePortScanner)

set(CMAKE_CXX_STANDARD 20)
find_package(Boost REQUIRED COMPONENTS program_options)



add_executable(simplePortScanner main.cpp
        src/PortScanner.hpp
        src/PortScanner.cpp
      )

target_link_libraries(simplePortScanner
        Boost::program_options
)
