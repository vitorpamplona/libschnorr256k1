/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Hardware-accelerated SHA-256 transforms with runtime dispatch.
 *
 * Each backend (x86_64 SHA-NI, ARM64 Crypto Extensions) lives in its own
 * translation unit, compiled with the architecture flags it needs. The
 * dispatch in sha256.c selects one at startup based on CPU features, so a
 * binary built with SHA-NI intrinsics still runs on CPUs that lack the
 * extension.
 *
 * x86_64: SHA-NI (Intel Goldmont+/Ice Lake-X+, AMD Zen+)
 *   SHA256RNDS2, SHA256MSG1, SHA256MSG2 — 4 rounds per instruction
 *
 * ARM64: Crypto Extensions (all ARMv8.0-A Android phones)
 *   SHA256H, SHA256H2, SHA256SU0, SHA256SU1 — 4 rounds per instruction
 *
 * Both achieve ~100-150ns per 64-byte block vs ~800ns in software.
 * For BIP-340 tagged hashes (96-160 bytes), this saves ~0.5-1µs per hash.
 */
#ifndef SECP256K1_SHA256_HW_H
#define SECP256K1_SHA256_HW_H

#include <stdint.h>

#if defined(__x86_64__) || defined(_M_X64)
#define SHA256_HW_X86_AVAILABLE 1
void sha256_transform_shani(uint32_t state[8], const uint8_t block[64]);
#else
#define SHA256_HW_X86_AVAILABLE 0
#endif

#if defined(__aarch64__)
#define SHA256_HW_ARM_AVAILABLE 1
void sha256_transform_armce(uint32_t state[8], const uint8_t block[64]);
#else
#define SHA256_HW_ARM_AVAILABLE 0
#endif

#endif /* SECP256K1_SHA256_HW_H */
