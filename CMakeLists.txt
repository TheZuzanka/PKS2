cmake_minimum_required(VERSION 3.9.6)
project(PKS_Analyzer_Base C)

set(CMAKE_C_STANDARD 99)

include(FindPCAP.cmake)

add_executable(PKS_Analyzer_Base main.c header.h file_management.c comunication_management.c printing_info.c analyze_frame.c ip_adresses_management.c utils.c handling_tcp.c handling_icmp.c handling_tftp.c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(PKS_Analyzer_Base ${CMAKE_CURRENT_SOURCE_DIR}/lib/wpcap.lib)