cmake_minimum_required(VERSION 3.20)
project(ion_dtn_mls_demo CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# macOS arm64
if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
  set(CMAKE_OSX_ARCHITECTURES arm64)
endif()

# Try to locate Homebrew OpenSSL if not provided
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
  execute_process(COMMAND brew --prefix openssl@3
                  OUTPUT_VARIABLE OPENSSL_PREFIX
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  if(EXISTS "${OPENSSL_PREFIX}")
    list(APPEND CMAKE_PREFIX_PATH "${OPENSSL_PREFIX}")
    set(OPENSSL_ROOT_DIR "${OPENSSL_PREFIX}")
  endif()
endif()

find_package(OpenSSL REQUIRED)

# Build MLSpp from subdir (recommended)
add_subdirectory(mlspp)

add_executable(mls_testing mls_testing.cpp)
target_link_libraries(mls_testing
  PRIVATE
    mlspp
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Optional rpath for Homebrew OpenSSL
if(APPLE AND DEFINED OPENSSL_PREFIX)
  set_target_properties(mls_testing PROPERTIES
    BUILD_RPATH "${OPENSSL_PREFIX}/lib"
  )
endif()