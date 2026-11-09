# libschnorr256k1

A fast, from-scratch BIP-340 Schnorr signature library on the secp256k1 curve.

Built for [Nostr](https://nostr.com) event verification where every microsecond
counts: batch verification amortizes the cost of verifying many signatures from
the same pubkey, a fast-verify mode skips the y-parity check for x-only keys,
and hardware-accelerated SHA-256 uses native instructions on ARM64 and x86_64.

## Features

- **BIP-340 Schnorr signatures** — sign, verify, and batch-verify
- **Variable-length messages** — not limited to 32-byte hashes
- **Same-pubkey batch verification** — BIP-340's weighted batch equation, 128-bit weights
- **Fast verify** — skip y-parity check (safe for Nostr x-only pubkeys)
- **X-only ECDH** — shared secret for NIP-44 encryption
- **Key operations** — create, compress, tweak-add, tweak-mul
- **SHA-256** — with BIP-340 tagged hashes, HW-accelerated on ARM64/x86_64
- **Zero dependencies** — pure C11, no allocator, no libc beyond `<string.h>`
- **Platform-tuned** — ARM64 crypto extensions, x86_64 BMI2/SHA, LTO

## Quick Start

```c
#include "schnorr256k1.h"

/* Call once at startup */
secp256k1c_init();

/* Sign */
uint8_t sig[64];
secp256k1c_schnorr_sign(sig, msg, msg_len, secret_key, aux_rand);

/* Verify */
int ok = secp256k1c_schnorr_verify(sig, msg, msg_len, x_only_pubkey);

/* Batch verify (same pubkey, N signatures) */
int all_ok = secp256k1c_schnorr_verify_batch(
    pubkey, sigs, msgs, msg_lens, count
);

/* ECDH shared secret */
uint8_t shared[32];
secp256k1c_ecdh_xonly(shared, their_xonly_pub, my_secret_key);
```

## API

All public functions are declared in [`include/schnorr256k1.h`](include/schnorr256k1.h).

| Function | Description |
|----------|-------------|
| `secp256k1c_init()` | Initialize precomputed tables (call once, thread-safe) |
| `secp256k1c_schnorr_sign()` | BIP-340 Schnorr sign (any message length) |
| `secp256k1c_schnorr_sign_with_pubkey()` | Sign with the cached 33-byte compressed pubkey (fast path: skips deriving it) |
| `secp256k1c_schnorr_sign_xonly()` | Sign with the x-only pubkey: derives the public key for its y parity, so no faster than `sign`; returns 0 if the key is not the secret's |
| `secp256k1c_schnorr_verify()` | Full BIP-340 verification |
| `secp256k1c_schnorr_verify_fast()` | Fast verify (skip y-parity, safe for Nostr) |
| `secp256k1c_schnorr_verify_batch()` | Batch verify N sigs from the same pubkey |
| `secp256k1c_pubkey_create()` | Derive uncompressed public key from secret key |
| `secp256k1c_pubkey_compress()` | Compress 65-byte pubkey to 33 bytes |
| `secp256k1c_seckey_verify()` | Check if a 32-byte buffer is a valid secret key |
| `secp256k1c_privkey_tweak_add()` | BIP-32 key derivation: `(key + tweak) mod n` |
| `secp256k1c_pubkey_tweak_mul()` | EC point multiplication: `pubkey * scalar` |
| `secp256k1c_ecdh_xonly()` | X-only ECDH shared secret |
| `secp256k1c_sha256()` | One-shot SHA-256 |
| `secp256k1c_tagged_hash()` | BIP-340 tagged hash |

All functions operate on byte arrays — no opaque context objects.

## Build

```bash
mkdir build && cd build
cmake ..
make
```

CMake options:

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | `ON` | Build the test suite |
| `BUILD_BENCH` | `ON` | Build the benchmark |
| `BUILD_BENCH_COMPARE` | `OFF` | Build comparison benchmark vs libsecp256k1 (requires `LIBSECP256K1_LIB`) |

Platform optimizations are detected automatically:

| Platform | Flags |
|----------|-------|
| ARM64 | `-march=armv8-a+crypto` (NEON + SHA) |
| x86_64 | `-march=x86-64-v2 -mbmi2 -msha -msse4.1` |
| Other | Portable `-O3` |

LTO is enabled when the toolchain supports it.

### Android (NDK)

```bash
./scripts/build_android.sh [OUTPUT_DIR]
```

Builds ARM64 and x86_64 static libraries using the Android NDK.

### iOS / macOS

Use CMake with the appropriate toolchain file:

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=ios.toolchain.cmake -DPLATFORM=OS64 ..
```

## Test

```bash
cd build
./test/schnorr256k1_tests
```

Or via CTest:

```bash
cd build
ctest
```

The test suite includes 125 tests across 7 files:

| File | Tests | Coverage |
|------|-------|----------|
| `test_schnorr.c` | 27 | Full BIP-340 test vectors (0-18), sign/verify round-trip, signing entry points |
| `test_secp256k1.c` | 28 | Key ops, ECDH symmetry, batch verify, point tables built and cached, tagged hash |
| `test_field.c` | 31 | Field arithmetic mod p against a reference, carry-fold regression |
| `test_point.c` | 14 | EC point doubling, addition, scalar multiplication |
| `test_key_codec.c` | 14 | Key parsing and validation, serialization, liftX |
| `test_sha256.c` | 8 | SHA-256 KATs, tagged hash consistency |
| `test_threads.c` | 3 | The shared caches and init under concurrent verifies (built where pthreads exist) |

All BIP-340 test vectors come from the
[official BIP-340 spec](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).

## Benchmark

```bash
cd build
./bench/secp256k1_bench
```

Sample output (x86_64, a 4-vCPU cloud VM, pinned to one core):

```
  pubkeyCreate                                  10.0 µs
  signSchnorr                                   20.9 µs
  signSchnorrWithPubkey (cached pubkey)         10.4 µs
  verifySchnorr                                 27.0 µs
  verifySchnorrFast                             25.4 µs
  verifyBatch(4)                                59.1 µs
  verifyBatch(16)                              183.0 µs
  verifyBatch(200)                           2,170.3 µs
  ecdhXOnly                                     23.7 µs
```

This benchmark repeats one signature and one key, so branch predictors and caches
see the same work every call, and the numbers come out lower than with varied
inputs. The [results below](#benchmark-results-libschnorr256k1-vs-libsecp256k1-bitcoin-core)
come from varied ones.

## Comparison Benchmark (vs libsecp256k1)

A head-to-head benchmark compares libschnorr256k1 against Bitcoin Core's
[libsecp256k1](https://github.com/bitcoin-core/secp256k1). Build libsecp256k1
first, then point CMake at the compiled library:

```bash
# Build libsecp256k1 (if you haven't already)
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
mkdir build && cd build
cmake .. -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
         -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
         -DBUILD_SHARED_LIBS=ON
make
cd ../..

# Build the comparison benchmark
cd libschnorr256k1/build
cmake .. -DBUILD_BENCH_COMPARE=ON \
         -DLIBSECP256K1_LIB=/path/to/secp256k1/build/lib/libsecp256k1.so
make schnorr256k1_bench_compare

# Run it
./schnorr256k1_bench_compare
```

The benchmark cross-verifies signatures between the two libraries before
timing, ensuring both are doing the same cryptographic work.

**What the results show** (the [tables below](#benchmark-results-libschnorr256k1-vs-libsecp256k1-bitcoin-core)):

- Signing and key creation take about a third less time than in libsecp256k1, and
  signing with a known public key a third of the time.
- Verifying real Nostr events takes about a fifth less time; with a new key every call
  (no cache can help), verification is level with libsecp256k1.
- ECDH and tweak-multiply are level with libsecp256k1.
- Batch verification of one author's signatures costs, from batch size 32 up, under
  40% of a single verification.

## Project Structure

```
libschnorr256k1/
├── include/
│   └── schnorr256k1.h         # Public API
├── src/
│   ├── secp256k1_internal.h   # Internal types, platform detection
│   ├── field.c / field.h      # Field arithmetic (4x64-bit limbs, mod p)
│   ├── field_asm.h            # ARM64 assembly for field multiply
│   ├── scalar.c / scalar.h    # Scalar arithmetic (mod n, GLV)
│   ├── point.c / point.h      # EC point ops, comb/GLV multiplication
│   ├── schnorr.c              # BIP-340, key ops, ECDH, SHA wrappers
│   ├── sha256.c / sha256.h    # SHA-256 + tagged hashes
│   └── sha256_hw.h            # HW-accelerated SHA-256
├── test/                      # 125 tests
├── bench/                     # Standalone benchmark
├── scripts/                   # Android NDK build script
├── CMakeLists.txt
└── LICENSE                    # MIT
```

## Design

This is **not** a fork of Bitcoin's `libsecp256k1`. It is a from-scratch
implementation written in C11 with these design choices:

- **4x64-bit limbs** for field elements (fewer multiplies than 5x52)
- **Comb method** for generator multiplication (~43 point lookups)
- **GLV endomorphism + wNAF** for arbitrary point multiplication
- **Strauss/Shamir + GLV** for dual scalar multiplication (verification)
- **Montgomery's trick** for batch affine conversion
- **Lazy reduction** — field operations defer normalization
- **Precomputed tables** initialized once at startup

## License

MIT. See [LICENSE](LICENSE).

## Benchmark Results: libschnorr256k1 vs libsecp256k1 (Bitcoin Core)

From [libschnorr256k1-bench](https://github.com/vitorpamplona/libschnorr256k1-bench)'s
c layer, which calls both libraries from C on the same inputs and checks every output
against the same digests before timing: libschnorr256k1 `2f4a13d` and libsecp256k1
`6e2c8bc`, each built with its own CMake flags (Release). Median µs per call, single
thread, on a 4-vCPU x86_64 cloud VM (Intel Xeon @ 2.10 GHz, a shared machine), 2026-11-09.
Every other library and language the bench covers is in its README.

### Individual Operations

| Operation | libschnorr256k1 (µs) | libsecp256k1 (µs) |
|-----------|---------------------:|------------------:|
| pubkeyCreate (65 bytes) | 10.6 | 15.4 |
| signSchnorr | 21.5 | 33.1 |
| signSchnorr, public key known | 10.9 | 34.5 |
| verifySchnorr, a new key each call | 36.1 | 36.8 |
| verifySchnorr, one key | 26.1 | 36.2 |
| verifySchnorrFast, one key | 24.8 | 33.8 (full verify) |
| ECDH (x-only) | 32.3 | 32.4 |
| tweak-mul (public key) | 32.2 | 31.6 |
| pubkey compress | 0.06 | 0.13 |

libsecp256k1 has no call that signs with a known public key, so its row is its plain
sign; and no fast verify, so its row is its full verify.

### Batch Verification (same pubkey)

libsecp256k1 has no same-pubkey batch API: it verifies N signatures with N
`schnorrsig_verify` calls. libschnorr256k1 checks BIP-340's batch equation, with a
128-bit weight per signature derived from all of the inputs, so invalid signatures
cannot cancel each other out. Per signature, each batch of different signatures by
one key, on a 4-vCPU x86_64 cloud VM (a shared machine), where a single verification
of the same signatures takes 28.4 µs (median of 15 rounds over 6,400 signatures,
pinned to one core, the same VM as above):

| Batch size | libschnorr256k1 (µs/sig) |
|-----------:|--------------------------:|
| 2 | 20.3 |
| 4 | 15.9 |
| 8 | 13.0 |
| 16 | 11.7 |
| 32 | 10.9 |
| 64 | 10.7 |
| 200 | 10.7 |

Each signature after the first costs a square root (to lift its R), a table of its
odd multiples and about 25 point additions; the doublings, the G and P terms and one
inversion per 64 signatures are shared by the batch.

### Real Nostr Events

The bench's dataset: 29,614 signed events from relays, by 4,926 authors, in the order
relays sent them (a few prolific authors and thousands seen once).

| Operation | libschnorr256k1 (µs) | libsecp256k1 (µs) |
|-----------|---------------------:|------------------:|
| verify each event | 31.1 | 38.2 |
| fast verify each event | 30.6 | 38.8 (full verify) |
| batch verify, pages of 200 batched by author (per event) | 18.9 | – |
| ECDH with each author's key | 33.0 | 33.6 |
