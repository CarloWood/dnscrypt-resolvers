cmake_minimum_required(VERSION 3.14...4.02)

project(public-resolvers-decoder
  LANGUAGES C CXX
  DESCRIPTION "Convert public-resolvers.md into JSON."
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Begin of gitache configuration.
set(GITACHE_PACKAGES libcwd_r)
include(cwm4/cmake/StableGitache)
# End of gitache configuration.

include(cwm4/cmake/AICxxProject NO_POLICY_SCOPE)

#Exit if someone tries to contaminates the source directory with an in-source build.
if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "Please do out-of-source builds.\nCleanup: \"rm -rf CMake CMakeCache.txt CMakeFiles/\"")
endif()

include(AICxxSubmodules)

add_executable(decoder
  decoder.cxx
  ResolverFlags.cxx
)

target_link_libraries(decoder
  PRIVATE
    ${AICXX_OBJECTS_LIST}
    enchantum::enchantum
)

add_executable(filter
  filter.cxx
  GeoLocation.cxx
  ResolverFlags.cxx
)

target_link_libraries(filter
  PRIVATE
    ${AICXX_OBJECTS_LIST}
    enchantum::enchantum
)

add_subdirectory(enchantum)
