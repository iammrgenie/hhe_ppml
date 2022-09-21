cmake_minimum_required(VERSION 3.13)

project(HHE_PPML_APP)

#find_package(SEAL 4.0.0 EXACT REQUIRED)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(hhe-server hhe-server.cpp)
add_executable(hhe-client hhe-client.cpp)

#target_link_libraries(hhe-client SEAL::seal_shared)
#target_link_libraries(hhe-server SEAL::seal_shared)