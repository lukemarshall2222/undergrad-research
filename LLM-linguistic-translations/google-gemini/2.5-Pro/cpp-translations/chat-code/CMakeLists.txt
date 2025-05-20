cmake_minimum_required(VERSION 3.15) # Increased requirement for target_link_options if needed

project(OcamlStreamTranslate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17) # Need C++17 for std::variant, std::optional, etc.
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Prefer standard C++

# Add source files
add_executable(stream_processor
    main.cpp
    common_utils.cpp
    builtins.cpp
    sonata_queries.cpp
)

# Optional: Improve warnings (GCC/Clang)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(stream_processor PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow          # Warn when variable shadows another
        -Wnon-virtual-dtor # Warn if base class has non-virtual destructor
        -Wold-style-cast  # Warn for C-style casts
        -Wcast-align      # Warn for potential performance issues from casts
        -Wunused          # Warn about unused variables/parameters
        -Woverloaded-virtual # Warn about missed overrides
        -Werror=return-type  # Error on missing return statement
    )
endif()


# Optional: Set build type if not specified by user (e.g., Debug for development)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose build type: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

# Optional: Enable AddressSanitizer for Debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "Enabling AddressSanitizer for Debug build")
    target_compile_options(stream_processor INTERFACE -fsanitize=address)
    target_link_options(stream_processor INTERFACE -fsanitize=address)
endif()


# Output message
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")