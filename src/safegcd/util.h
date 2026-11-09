/*
 * The few definitions from libsecp256k1's src/util.h that its modinv64 and int128 code
 * (vendored unmodified beside this file, from bitcoin-core/secp256k1 v0.8.0, MIT, see COPYING)
 * needs. Only the native __int128 path is used: field_inv.c includes this code only when
 * HAVE_INT128 is set, and keeps the Fermat inversion otherwise.
 */
#ifndef SCHNORR256K1_SAFEGCD_UTIL_H
#define SCHNORR256K1_SAFEGCD_UTIL_H

#include <stdint.h>

#define SECP256K1_INLINE inline
#define SECP256K1_GNUC_EXT __extension__

#define SECP256K1_WIDEMUL_INT128 1
#define SECP256K1_INT128_NATIVE 1

/* libsecp256k1's VERIFY build checks these; the release build compiles them out. */
#define VERIFY_CHECK(cond)

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/* Number of trailing zero bits of a non-zero x (variable time; used only by modinv64_var). */
static SECP256K1_INLINE int secp256k1_ctz64_var(uint64_t x) {
    return __builtin_ctzll(x);
}

#endif /* SCHNORR256K1_SAFEGCD_UTIL_H */
