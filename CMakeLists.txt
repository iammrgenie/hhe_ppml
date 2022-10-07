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
add_executable(3-party-hhe-server experiments/3-party-HHE/server.cpp)
add_executable(3-party-hhe-user experiments/3-party-HHE/user.cpp)
add_executable(3-party-hhe-analyst experiments/3-party-HHE/analyst.cpp)

add_executable(2-party-hhe-user experiments/2-party-HHE/user.cpp)
add_executable(2-party-hhe-server experiments/2-party-HHE/server.cpp)

add_executable(3-party-he-server experiments/3-party-HE/server.cpp)
add_executable(3-party-he-user experiments/3-party-HE/user.cpp)
add_executable(3-party-he-analyst experiments/3-party-HE/analyst.cpp)

add_executable(2-party-he-user experiments/2-party-HE/user.cpp)
add_executable(2-party-he-server experiments/2-party-HE/server.cpp)

add_executable(simple-hhe protocols/simple_hhe.cpp)

# --------------- Link the Executables with the Source Files --------------------
target_sources(3-party-hhe-server
        PRIVATE
            experiments/3-party-HHE/server.cpp           
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(3-party-hhe-user
        PRIVATE
            experiments/3-party-HHE/user.cpp           
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(3-party-hhe-analyst
        PRIVATE
            experiments/3-party-HHE/analyst.cpp           
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(2-party-hhe-user
        PRIVATE
            experiments/2-party-HHE/user.cpp           
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(2-party-hhe-server
        PRIVATE
            experiments/2-party-HHE/server.cpp           
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(3-party-he-user
        PRIVATE
            experiments/3-party-HE/user.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(3-party-he-server
        PRIVATE
            experiments/3-party-HE/server.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(3-party-he-analyst
        PRIVATE
            experiments/3-party-HE/analyst.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(2-party-he-user
        PRIVATE
            experiments/2-party-HE/user.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(2-party-he-server
        PRIVATE
            experiments/2-party-HE/server.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

target_sources(simple-hhe
        PRIVATE
            protocols/simple_hhe.cpp        
            src/SEAL_Cipher.cpp
            src/pasta_3_seal.cpp
            src/pasta_3_plain.cpp
            src/utils.cpp
            configs/config.cpp
)

# --------------------------- Specify libraries or flags to use when linking a given target and/or its dependents ----------------
target_link_libraries(3-party-hhe-server SEAL::seal keccak aes)
target_link_libraries(3-party-hhe-user SEAL::seal keccak aes)
target_link_libraries(3-party-hhe-analyst SEAL::seal keccak aes)
target_link_libraries(2-party-hhe-user SEAL::seal keccak aes)
target_link_libraries(2-party-hhe-server SEAL::seal keccak aes)

target_link_libraries(3-party-he-server SEAL::seal keccak aes)
target_link_libraries(3-party-he-user SEAL::seal keccak aes)
target_link_libraries(3-party-he-analyst SEAL::seal keccak aes)
target_link_libraries(2-party-he-server SEAL::seal keccak aes)
target_link_libraries(2-party-he-user SEAL::seal keccak aes)

target_link_libraries(simple-hhe SEAL::seal keccak aes)
