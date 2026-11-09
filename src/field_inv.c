/*
 * Field inversion by safegcd (Bernstein-Yang, as libsecp256k1 implements it): libsecp256k1's
 * modinv64, vendored unmodified in src/safegcd/ (MIT, Peter Dettman, see src/safegcd/COPYING),
 * on the 4x64 field elements through its signed62 representation.
 *
 *   fe_inv      constant time in its input: for values that may depend on a secret
 *               (public keys and signatures being made, ECDH, tweaks).
 *   fe_inv_var  variable time, faster: only for public values (verification, and tables of
 *               points that are public).
 *
 * Without __int128 both fall back to the Fermat exponentiation (field.c, fe_inv_fermat).
 */
#include "field.h"

#if HAVE_INT128

#if defined(__GNUC__)
#pragma GCC diagnostic push
/* modinv64.h also declares the Jacobi symbol helper, which nothing here uses. */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "safegcd/int128_native_impl.h"
#include "safegcd/modinv64_impl.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

/* p = 2^256 - 0x1000003D1 in signed62 limbs, and p^-1 mod 2^62 (libsecp256k1's
 * secp256k1_const_modinfo_fe, field_5x52_impl.h). */
static const secp256k1_modinv64_modinfo FE_MODINFO = {
    {{-0x1000003D1LL, 0, 0, 0, 256}},
    0x27C7F6E22DDACACFLL
};

#define M62 (UINT64_MAX >> 2)

/* a must be normalized (< p). */
static void fe_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_fe *a) {
    const uint64_t a0 = a->d[0], a1 = a->d[1], a2 = a->d[2], a3 = a->d[3];
    r->v[0] = (int64_t)(a0 & M62);
    r->v[1] = (int64_t)((a0 >> 62 | a1 << 2) & M62);
    r->v[2] = (int64_t)((a1 >> 60 | a2 << 4) & M62);
    r->v[3] = (int64_t)((a2 >> 58 | a3 << 6) & M62);
    r->v[4] = (int64_t)(a3 >> 56);
}

/* a's limbs must be in [0, 2^62) and its value below p, as modinv64 leaves them. */
static void fe_from_signed62(secp256k1_fe *r, const secp256k1_modinv64_signed62 *a) {
    const uint64_t a0 = (uint64_t)a->v[0], a1 = (uint64_t)a->v[1], a2 = (uint64_t)a->v[2],
                   a3 = (uint64_t)a->v[3], a4 = (uint64_t)a->v[4];
    r->d[0] = a0 | a1 << 62;
    r->d[1] = a1 >> 2 | a2 << 60;
    r->d[2] = a2 >> 4 | a3 << 58;
    r->d[3] = a3 >> 6 | a4 << 56;
}

void fe_inv(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe t = *a;
    secp256k1_modinv64_signed62 s;
    fe_normalize(&t);
    fe_to_signed62(&s, &t);
    secp256k1_modinv64(&s, &FE_MODINFO);
    fe_from_signed62(r, &s);
}

void fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe t = *a;
    secp256k1_modinv64_signed62 s;
    fe_normalize(&t);
    fe_to_signed62(&s, &t);
    secp256k1_modinv64_var(&s, &FE_MODINFO);
    fe_from_signed62(r, &s);
}

#else /* !HAVE_INT128 */

void fe_inv(secp256k1_fe *r, const secp256k1_fe *a) { fe_inv_fermat(r, a); }

void fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a) { fe_inv_fermat(r, a); }

#endif /* HAVE_INT128 */
