cmake_minimum_required(VERSION 3.18)
project(schnorr256k1 C)

set(CMAKE_C_STANDARD 11)

# ==================== Options ====================

option(BUILD_TESTS "Build tests" ON)
option(BUILD_BENCH "Build benchmarks" ON)
option(BUILD_BENCH_COMPARE "Build comparison benchmark against libsecp256k1" OFF)

# ==================== Link-Time Optimization ====================
#
# LTO lets the linker inline fe_mul / fe_sqr across translation units
# (field.c <-> point.c <-> scalar.c <-> schnorr.c), recovering ~5-15% on the
# hot Jacobian formulas where fe_mul would otherwise be a call boundary.
# Disabled automatically when the toolchain doesn't support it.

include(CheckIPOSupported)
check_ipo_supported(RESULT LTO_SUPPORTED OUTPUT LTO_ERROR)
if(LTO_SUPPORTED)
    message(STATUS "LTO supported - enabling interprocedural optimization")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(STATUS "LTO not supported: ${LTO_ERROR}")
endif()

# ==================== Platform-specific optimizations ====================

# When cross-compiling on Apple platforms via CMAKE_OSX_ARCHITECTURES (e.g. building
# x86_64 from an Apple Silicon host), CMAKE_SYSTEM_PROCESSOR still reflects the host
# arch — so prefer the explicit target arch from CMAKE_OSX_ARCHITECTURES if set.
if(CMAKE_OSX_ARCHITECTURES)
    list(GET CMAKE_OSX_ARCHITECTURES 0 SCHNORR256K1_TARGET_ARCH)
else()
    set(SCHNORR256K1_TARGET_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif()

#
# The hardware SHA-256 backends (x86 SHA-NI, ARM64 Crypto Extensions) are
# isolated in their own translation units (src/sha256_hw_x86.c,
# src/sha256_hw_arm.c) and compiled with their architecture flags applied
# only to those files. Keeping -msha / +crypto out of the base PLATFORM_FLAGS
# means the rest of the library (and its dispatcher in sha256.c) runs on any
# x86-64-v2 / ARMv8-A CPU even when SHA-NI / Crypto Extensions are absent.
if(SCHNORR256K1_TARGET_ARCH MATCHES "aarch64|arm64|ARM64")
    message(STATUS "ARM64 detected - NEON baseline; SHA2 dispatched at runtime")
    set(PLATFORM_FLAGS "-march=armv8-a -O3 -fomit-frame-pointer")
    set(SHA256_HW_X86 OFF)
    set(SHA256_HW_ARM ON)
elseif(SCHNORR256K1_TARGET_ARCH MATCHES "x86_64|AMD64|amd64")
    message(STATUS "x86_64 detected - SSE4.1/BMI2 baseline; SHA-NI dispatched at runtime")
    set(PLATFORM_FLAGS "-march=x86-64-v2 -mbmi2 -msse4.1 -O3 -fomit-frame-pointer")
    set(SHA256_HW_X86 ON)
    set(SHA256_HW_ARM OFF)
else()
    message(STATUS "Generic platform - using portable implementation")
    set(PLATFORM_FLAGS "-O3 -fomit-frame-pointer")
    set(SHA256_HW_X86 OFF)
    set(SHA256_HW_ARM OFF)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PLATFORM_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")

# ==================== Core static library ====================

set(SECP256K1_SOURCES
    src/field.c
    src/scalar.c
    src/point.c
    src/schnorr.c
    src/sha256.c
)

if(SHA256_HW_X86)
    list(APPEND SECP256K1_SOURCES src/sha256_hw_x86.c)
endif()
if(SHA256_HW_ARM)
    list(APPEND SECP256K1_SOURCES src/sha256_hw_arm.c)
endif()

add_library(schnorr256k1 STATIC ${SECP256K1_SOURCES})
target_include_directories(schnorr256k1
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Per-TU flags for the hardware-accelerated backends. SHA-NI / Crypto
# Extensions intrinsics may only emit their special opcodes from these files;
# nothing else in the library is built with these flags, so the baseline ABI
# stays compatible with the broader -march target.
if(SHA256_HW_X86)
    set_source_files_properties(src/sha256_hw_x86.c PROPERTIES
        COMPILE_OPTIONS "-msha;-mssse3;-msse4.1")
endif()
if(SHA256_HW_ARM)
    set_source_files_properties(src/sha256_hw_arm.c PROPERTIES
        COMPILE_OPTIONS "-march=armv8-a+crypto")
endif()

# ==================== Optional components ====================

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(BUILD_BENCH)
    add_subdirectory(bench)
endif()

# ==================== Comparison benchmark ====================

if(BUILD_BENCH_COMPARE)
    if(NOT LIBSECP256K1_LIB)
        message(FATAL_ERROR
            "BUILD_BENCH_COMPARE requires -DLIBSECP256K1_LIB=/path/to/libsecp256k1.so")
    endif()

    add_executable(schnorr256k1_bench_compare bench/bench_vs_libsecp256k1.c)
    target_link_libraries(schnorr256k1_bench_compare PRIVATE schnorr256k1)
    target_include_directories(schnorr256k1_bench_compare PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_link_libraries(schnorr256k1_bench_compare PRIVATE ${LIBSECP256K1_LIB})
    if(UNIX)
        target_link_libraries(schnorr256k1_bench_compare PRIVATE m)
    endif()
endif()

# ==================== Install rules ====================

install(TARGETS schnorr256k1
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
install(FILES include/schnorr256k1.h DESTINATION include)
