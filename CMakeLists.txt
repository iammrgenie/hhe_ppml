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
link_directories(/usr/local/lib)

# add_executable(hhe-server hhe-server.cpp)
# add_executable(hhe-client hhe-client.cpp)
add_executable(hhe-analyst analyst.cpp)                            #Checking the PASTA implementation
# add_executable(hhe-test)                            #Checking the PASTA implementation

target_sources(hhe-analyst
        PRIVATE
            analyst.cpp            
            SEAL_Cipher.cpp
            pasta_3_seal.cpp
            pasta_3_plain.cpp
)

#target_link_libraries(hhe-client SEAL::seal)
#target_link_libraries(hhe-client SEAL::seal_shared) # for Mac
#target_link_libraries(hhe-server SEAL::seal)
#target_link_libraries(hhe-server SEAL::seal_shared) # for Mac
# target_link_libraries(hhe-test SEAL::seal keccak aes)
target_link_libraries(hhe-analyst SEAL::seal keccak aes)