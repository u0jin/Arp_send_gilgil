cmake_minimum_required(VERSION 3.14)
project(arp_gilgil)

set(CMAKE_CXX_STANDARD 14)

add_executable(arp_gilgil main.cpp)
target_link_libraries(arp_gilgil pcap)