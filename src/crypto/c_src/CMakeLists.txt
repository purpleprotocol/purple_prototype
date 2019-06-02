cmake_minimum_required(VERSION 3.3)
project(bls CXX ASM)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
set(CMAKE_MACOSX_RPATH 1)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
set(LIBS mcl)
set(GPP_FLAGS "-DMCL_USE_VINT -DMCL_VINT_FIXED_BUFFER -DMCL_DONT_USE_OPENSSL")

include_directories(bls/include/)
include_directories(mcl/include/)
add_subdirectory(mcl)

if (WIN32)
add_subdirectory(cybozulib_ext)
include_directories(cybozulib_ext/include/)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(bls_c256 SHARED bls/src/bls_c256.cpp)
add_library(bls_c384 SHARED bls/src/bls_c384.cpp)
add_library(bls_c384_256 SHARED bls/src/bls_c384_256.cpp)
target_link_libraries(bls_c256 ${LIBS})
target_link_libraries(bls_c384 ${LIBS})
target_link_libraries(bls_c384_256 ${LIBS})
set_target_properties(mcl PROPERTIES COMPILE_FLAGS ${GPP_FLAGS})
set_target_properties(bls_c256 PROPERTIES COMPILE_FLAGS ${GPP_FLAGS})
set_target_properties(bls_c384 PROPERTIES COMPILE_FLAGS ${GPP_FLAGS})
set_target_properties(bls_c384_256 PROPERTIES COMPILE_FLAGS ${GPP_FLAGS})

file(GLOB BLS_HEADERS bls/include/bls/bls.h bls/include/bls/bls.hpp)

install(TARGETS bls_c256 DESTINATION lib)
install(TARGETS bls_c384 DESTINATION lib)
install(TARGETS bls_c384_256 DESTINATION lib)
install(FILES ${BLS_HEADERS} DESTINATION include/bls)