cmake_minimum_required(VERSION 3.13)

project(HHE_PPML_APP)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

find_package(SEAL 4.0.0 EXACT REQUIRED)

include(CheckCCompilerFlag)
function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    add_compile_options("${flag}")
  endif()
endfunction()

# for AES code
if(MSVC)
  add_definitions("-DOC_ENABLE_SSE2")
  message("-- Enabling SSE2 for AES")
  add_definitions("-DOC_ENABLE_AESNI")
  message("-- Enabling AES_NI")
else()
  check_c_compiler_flag_and_add(-msse2 CC_SUPPORTS_SSE2)
  if(CC_SUPPORTS_SSE2)
    add_definitions("-DOC_ENABLE_SSE2")
    message("-- Enabling SSE2 for AES")
  endif()

  check_c_compiler_flag_and_add(-maes CC_SUPPORTS_AES)
  if(CC_SUPPORTS_AES)
    add_definitions("-DOC_ENABLE_AESNI")
    message("-- Enabling AES_NI")
  else()
    add_definitions("-DOC_ENABLE_PORTABLE_AES")
  endif()
endif()

add_subdirectory(util)

include_directories(/usr/local/include)
include_directories(src)
link_directories(/usr/local/lib)

# --------------- Create the Executables for Testing ---------------------------
add_executable(3-party-server 3-party-HHE/server.cpp)                             #Server in 3-party implementation
# add_executable(3-party-client 3-party-HHE/client.cpp)                             #Client in 3-party implementation
add_executable(3-party-analyst 3-party-HHE/analyst.cpp)                           #Analyst in 3-party implementation

# add_executable(3-party-server 3-party-HHE/server.cpp)                             #Server in 3-party implementation
# add_executable(3-party-server 3-party-HHE/server.cpp)                             #Server in 3-party implementation
# add_executable(3-party-server 3-party-HHE/server.cpp)                             #Server in 3-party implementation
# add_executable(3-party-server 3-party-HHE/server.cpp)                             #Server in 3-party implementation
# add_executable(3-party-server 3-party-HHE/server.cpp)                             #Server in 3-party implementation
# add_executable(one-party-hhe tests/one_party_hhe.cpp)                               #The Server in our implementation

# add_executable(server-test hhe-server.cpp)
# add_executable(client-test hhe-client.cpp) 


# --------------- Link the Executables with the Source Files --------------------
target_sources(3-party-server
        PRIVATE
            3-party-HHE/server.cpp           
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
)

# target_sources(3-party-user
#         PRIVATE
#             3-party-HHE/user.cpp           
#             src/SEAL_Cipher.cpp
#             src/pasta_3_seal.cpp
#             src/pasta_3_plain.cpp
#             src/utils.cpp
# )

target_sources(3-party-analyst
        PRIVATE
            3-party-HHE/analyst.cpp           
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
)

target_link_libraries(3-party-server SEAL::seal keccak aes)
# target_link_libraries(3-party-user SEAL::seal keccak aes)
target_link_libraries(3-party-analyst SEAL::seal keccak aes)

