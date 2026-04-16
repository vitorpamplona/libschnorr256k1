# CLAUDE.md — Project Guidelines for libschnorr256k1

## What This Is

A from-scratch BIP-340 Schnorr signature library on secp256k1, extracted from the Amethyst Nostr client. Pure C11, zero dependencies, designed for maximum throughput on mobile and desktop.

## Critical: Performance Is the Primary Goal

This library exists because the generic libsecp256k1 wasn't fast enough for Nostr event verification. Every change must preserve or improve performance.

### Platform-Specific Assembly and Intrinsics

The hardware-accelerated code paths are the most sensitive parts of the codebase:

- **`src/sha256_hw.h`** — SHA-256 using ARM64 Crypto Extensions (SHA256H/SHA256H2/SHA256SU0/SHA256SU1) and x86_64 SHA-NI (SHA256RNDS2/SHA256MSG1/SHA256MSG2). These process 4 rounds per instruction and are ~5-8x faster than software.
- **`src/field_asm.h`** — ARM64 assembly for field multiplication (UMULH/UMULL). This is on the hottest path in the library (every EC point operation calls it).
- **`src/field.c`** — x86_64 field arithmetic using `__int128` for 64x64->128 multiply.

When modifying these files:
- Trace the register/variable state through every round. Off-by-one in register naming silently produces wrong results (not crashes).
- The ARM64 and x86_64 paths use different macro structures and different argument orderings. Do not assume one mirrors the other.
- Test on BOTH x86_64 and ARM64. The test suite will catch correctness bugs (SHA-256 KATs, BIP-340 test vectors) but only if run on the affected platform.
- Never add branches or memory accesses to hot loops without benchmarking.

### Performance-Sensitive Design Choices

- **4x64-bit limbs** for field elements (fewer multiplies than 5x52-bit)
- **Comb method** for generator multiplication (~43 point lookups)
- **GLV endomorphism + wNAF** for arbitrary-point scalar multiplication
- **Strauss/Shamir + GLV** for dual-scalar multiplication (verification)
- **Lazy reduction** — field operations defer normalization
- **Precomputed tables** initialized once at startup (secp256k1c_init)
- **Montgomery's trick** for batch affine conversion

Do not replace these with simpler alternatives without benchmarking proof.

## Build and Test

```bash
mkdir build && cd build
cmake ..
make
./test/schnorr256k1_tests    # Expect: ALL 103 TESTS PASSED
ctest                         # Expect: 100% tests passed
./bench/secp256k1_bench       # Benchmark all operations
```

## Architecture

- **Public API**: `include/schnorr256k1.h` — byte-array interface, no opaque contexts
- **Internal types**: `src/secp256k1_internal.h` — secp256k1_fe, secp256k1_scalar, secp256k1_gej, secp256k1_ge
- Internal types must never leak into the public header.
- No source file should reference the old header name `secp256k1_c.h`.

## Code Conventions

- C11, no allocator, no libc beyond `<string.h>` and `<stdint.h>`
- No external dependencies
- Constant-time operations where cryptographically required (signing, key operations)
- Warnings: `-Wall -Wextra`; the only expected warning is `-Wunused-const-variable` on the software-fallback K array in sha256.c when the HW path is active
