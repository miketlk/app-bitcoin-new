cmake_minimum_required(VERSION 3.10)

if(NOT WIN32)
  string(ASCII 27 Esc)
  set(ColourReset "${Esc}[m")
  set(ColourBold "${Esc}[1m")
  set(Red "${Esc}[31m")
  set(Green "${Esc}[32m")
  set(Yellow "${Esc}[33m")
  set(Blue "${Esc}[34m")
  set(Magenta "${Esc}[35m")
  set(Cyan "${Esc}[36m")
  set(White "${Esc}[37m")
  set(BoldRed "${Esc}[1;31m")
  set(BoldGreen "${Esc}[1;32m")
  set(BoldYellow "${Esc}[1;33m")
  set(BoldBlue "${Esc}[1;34m")
  set(BoldMagenta "${Esc}[1;35m")
  set(BoldCyan "${Esc}[1;36m")
  set(BoldWhite "${Esc}[1;37m")
endif()

if(${CMAKE_VERSION} VERSION_LESS 3.10)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
  VERSION 0.1
  DESCRIPTION "Unit tests for Ledger Nano application"
  LANGUAGES C)

# guard against bad build-type strings
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

if(CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
  set(GCC_COVERAGE_LINK_FLAGS "--coverage")
  set(GCOV_LIB "")
  set(LIB_TYPE STATIC)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wno-newline-eof")
else()
  set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
  set(GCOV_LIB "gcov")
  set(LIB_TYPE SHARED)
endif()

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

add_compile_definitions(TEST DEBUG=0 SKIP_FOR_CMOCKA PRINTF=printf)

if(NOT DEFINED HAVE_LIQUID OR HAVE_LIQUID GREATER_EQUAL 1)
  set(HAVE_LIQUID 1)
  add_compile_definitions(HAVE_LIQUID)
endif()

if(HAVE_LIQUID)
  message("${BoldCyan}** LIQUID SUPPORT ENABLED **${ColourReset}")
endif()

include_directories(../src)
include_directories(../src/common)
include_directories(mock_includes)
include_directories(lib/sha-2)

if(CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
  include_directories(/usr/local/include)
  link_directories(/usr/local/lib)
endif()

include_directories(libs)

add_executable(test_apdu_parser test_apdu_parser.c)
add_executable(test_base58 test_base58.c)
add_executable(test_bip32 test_bip32.c)
add_executable(test_bitvector test_bitvector.c)
add_executable(test_buffer test_buffer.c)
add_executable(test_format test_format.c)
add_executable(test_display_utils test_display_utils.c)
add_executable(test_parser test_parser.c)
add_executable(test_script test_script.c)
add_executable(test_wallet test_wallet.c)
add_executable(test_write test_write.c)
add_executable(test_crypto test_crypto.c)

# Mock libraries
add_library(crypto_mocks ${LIB_TYPE} libs/crypto_mocks.c)
add_library(sha256 ${LIB_TYPE} libs/sha-256.c)

if(HAVE_LIQUID)
  add_executable(test_liquid_addr test_liquid_addr.c)
  add_executable(test_liquid test_liquid.c)
  add_executable(test_liquid_assets test_liquid_assets.c)
  add_executable(test_contract_parser test_contract_parser.c)
  add_executable(test_asset_metadata test_asset_metadata.c)
endif()

# App's libraries
add_library(apdu_parser ${LIB_TYPE} ../src/boilerplate/apdu_parser.c)
add_library(base58 ${LIB_TYPE} ../src/common/base58.c)
add_library(bip32 ${LIB_TYPE} ../src/common/bip32.c)
add_library(buffer ${LIB_TYPE} ../src/common/buffer.c)
add_library(display_utils ${LIB_TYPE} ../src/ui/display_utils.c)
add_library(format ${LIB_TYPE} ../src/common/format.c)
add_library(parser ${LIB_TYPE} ../src/common/parser.c)
add_library(read ${LIB_TYPE} ../src/common/read.c)
add_library(script ${LIB_TYPE} ../src/common/script.c)
add_library(varint ${LIB_TYPE} ../src/common/varint.c)
add_library(wallet ${LIB_TYPE} ../src/common/wallet.c)
add_library(write ${LIB_TYPE} ../src/common/write.c)
add_library(crypto ${LIB_TYPE} ../src/crypto.c)

if(HAVE_LIQUID)
  add_library(liquid ${LIB_TYPE} ../src/liquid/liquid.c ../src/liquid/liquid_addr.c ../src/liquid/blech32.c ../src/liquid/liquid_assets.c ../src/liquid/contract_parser.c ../src/liquid/liquid_asset_metadata.c ../src/liquid/liquid_wallet.c)
  set(LIQUID_LIB "liquid")
else()
  set(LIQUID_LIB "")
endif()

# Mock libraries
target_link_libraries(crypto_mocks PUBLIC sha256)

# App's libraries
target_link_libraries(test_apdu_parser PUBLIC cmocka ${GCOV_LIB} apdu_parser)
target_link_libraries(test_base58 PUBLIC cmocka ${GCOV_LIB} base58 crypto_mocks)
target_link_libraries(test_bip32 PUBLIC cmocka ${GCOV_LIB} bip32 read)
target_link_libraries(test_bitvector PUBLIC cmocka ${GCOV_LIB})
target_link_libraries(test_buffer PUBLIC cmocka ${GCOV_LIB} buffer varint read write bip32)
target_link_libraries(test_display_utils PUBLIC cmocka ${GCOV_LIB} display_utils)
target_link_libraries(test_format PUBLIC cmocka ${GCOV_LIB} format)
target_link_libraries(test_parser PUBLIC cmocka ${GCOV_LIB} parser buffer varint read write bip32)
target_link_libraries(test_script PUBLIC cmocka ${GCOV_LIB} script buffer varint read write bip32)
target_link_libraries(test_wallet PUBLIC cmocka ${GCOV_LIB} ${LIQUID_LIB} wallet script buffer varint read write bip32 base58 crypto crypto_mocks)
target_link_libraries(test_write PUBLIC cmocka ${GCOV_LIB} write)
target_link_libraries(test_crypto PUBLIC cmocka ${GCOV_LIB} crypto read base58 crypto_mocks)

if(HAVE_LIQUID)
  target_link_libraries(test_liquid_addr PUBLIC cmocka ${GCOV_LIB} liquid buffer varint bip32 base58 read write crypto_mocks)
  target_link_libraries(test_liquid PUBLIC cmocka ${GCOV_LIB} liquid wallet script buffer varint bip32 base58 read write crypto crypto_mocks)
  target_link_libraries(test_liquid_assets PUBLIC cmocka ${GCOV_LIB} liquid write crypto_mocks)
  target_link_libraries(test_contract_parser PUBLIC cmocka ${GCOV_LIB} liquid wallet script buffer varint read write bip32 base58 crypto_mocks)
  target_link_libraries(test_asset_metadata PUBLIC cmocka ${GCOV_LIB} liquid buffer varint read write bip32 crypto_mocks)
endif()

add_test(test_apdu_parser test_apdu_parser)
add_test(test_base58 test_base58)
add_test(test_bip32 test_bip32)
add_test(test_bitvector test_bitvector)
add_test(test_buffer test_buffer)
add_test(test_display_utils test_display_utils)
add_test(test_format test_format)
add_test(test_parser test_parser)
add_test(test_script test_script)
add_test(test_wallet test_wallet)
add_test(test_write test_write)
add_test(test_crypto test_crypto)

if(HAVE_LIQUID)
  add_test(test_liquid_addr test_liquid_addr)
  add_test(test_liquid test_liquid)
  add_test(test_liquid_assets test_liquid_assets)
  add_test(test_contract_parser test_contract_parser)
  add_test(test_asset_metadata test_asset_metadata)
endif()
