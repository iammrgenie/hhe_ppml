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

add_executable(hhe-server hhe-server.cpp)                               #The Server in our implementation
add_executable(hhe-client hhe-client.cpp)                               #The Client in our implementation
# add_executable(hhe-analyst hhe-analyst.cpp)                             #The Analyst in our implementation

#add_executable(hhe-test)                                               #Checking the PASTA implementation
add_executable(one-party-hhe tests/one_party_hhe.cpp)                            #Checking the PASTA implementation
# add_executable(pasta-simple-test pasta_test_new.cpp)                   #Checking the PASTA simplification implementation
# add_executable(key-encryption-test tests/key_encryption_test.cpp)                   #Checking the PASTA simplification implementation
# add_executable(pasta-check pasta_check.cpp)                            #Checking the PASTA implementation
#add_executable(pasta-simple-test pasta_test_new.cpp)                   #Checking the PASTA simplification implementation

# target_sources(hhe-analyst
#         PRIVATE
#             hhe-analyst.cpp            
#             SEAL_Cipher.cpp
#             pasta_3_seal.cpp
#             pasta_3_plain.cpp
# )

target_sources(hhe-server
        PRIVATE
            hhe-server.cpp            
            SEAL_Cipher.cpp
            pasta_3_seal.cpp
            pasta_3_plain.cpp
)

target_sources(hhe-client
        PRIVATE
            hhe-client.cpp            
            SEAL_Cipher.cpp
            pasta_3_seal.cpp
            pasta_3_plain.cpp
)

# target_sources(pasta-check
#        PRIVATE
#            pasta_check.cpp            
#            SEAL_Cipher_old.cpp
#            pasta_3_seal_old.cpp
#            pasta_3_plain.cpp
# )

target_sources(one-party-hhe
       PRIVATE
           tests/one_party_hhe.cpp            
           pasta_modified_1/SEAL_Cipher.cpp
           pasta_modified_1/pasta_3_seal.cpp
           pasta_modified_1/pasta_3_plain.cpp
)

# target_sources(pasta-simple-test
#         PRIVATE
#             pasta_test_new.cpp            
#             SEAL_Cipher.cpp
#             pasta_3_seal.cpp
#             pasta_3_plain.cpp
# )


# target_sources(pasta-simple-test
#         PRIVATE
#             pasta_test_new.cpp            
#             SEAL_Cipher.cpp
#             pasta_3_seal.cpp
#             pasta_3_plain.cpp
# )

# target_sources(key-encryption-test
#         PRIVATE
#             tests/key_encryption_test.cpp            
#             SEAL_Cipher.cpp
#             pasta_3_seal.cpp
#             pasta_3_plain.cpp
#             pasta_original/SEAL_Cipher_original.cpp
#             pasta_original/pasta_3_seal_original.cpp
#             pasta_original/pasta_3_plain_original.cpp
# )


#target_link_libraries(hhe-analyst SEAL::seal keccak aes)
target_link_libraries(hhe-client SEAL::seal keccak aes)
target_link_libraries(hhe-server SEAL::seal keccak aes)
# target_link_libraries(pasta-check SEAL::seal keccak aes)
# target_link_libraries(pasta-simple-test SEAL::seal keccak aes)
# target_link_libraries(key-encryption-test SEAL::seal keccak aes)
target_link_libraries(one-party-hhe SEAL::seal keccak aes)
#target_link_libraries(pasta-simple-test SEAL::seal keccak aes)
