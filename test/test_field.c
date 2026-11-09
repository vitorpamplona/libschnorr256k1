/*
 * Copyright (c) 2025 Vitor Pamplona
 * Field arithmetic tests (mod p). Ported from FieldPTest.kt
 */
#include "test_framework.h"
#include "field.h"

/* Helper: hex string → field element */
static void fe_hex(secp256k1_fe *r, const char *hex) {
    uint8_t bytes[32];
    hex_to_bytes(bytes, hex, 32);
    fe_from_bytes(r, bytes);
}

/* Helper: field element → hex string comparison */
static void fe_to_hex(char *out, const secp256k1_fe *a) {
    uint8_t bytes[32];
    secp256k1_fe t = *a;
    fe_to_bytes(bytes, &t);
    for (int i = 0; i < 32; i++) {
        out[i*2]   = "0123456789abcdef"[bytes[i] >> 4];
        out[i*2+1] = "0123456789abcdef"[bytes[i] & 0xf];
    }
    out[64] = '\0';
}

static int fe_hex_eq(const secp256k1_fe *a, const char *hex) {
    char got[65];
    fe_to_hex(got, a);
    return strcmp(got, hex) == 0;
}

/* ==================== Basic Identities ==================== */

static void add_zero_identity(void) {
    secp256k1_fe a, zero, r;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    zero = FE_ZERO;
    fe_add(&r, &a, &zero);
    ASSERT_TRUE(fe_hex_eq(&r, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530"));
}

static void sub_self_is_zero(void) {
    secp256k1_fe a, neg_a, r;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_negate(&neg_a, &a, 1);
    fe_add(&r, &a, &neg_a);
    fe_normalize(&r);
    ASSERT_TRUE(fe_is_zero(&r));
}

static void add_then_sub_roundtrips(void) {
    secp256k1_fe a, b, sum, neg_b, back;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_hex(&b, "3982f19bef1615bccfbb05e321c10e1d4cba3df0e841c2e41eeb6016347653c3");
    fe_add(&sum, &a, &b);
    fe_negate(&neg_b, &b, 1);
    fe_add(&back, &sum, &neg_b);
    ASSERT_TRUE(fe_hex_eq(&back, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530"));
}

static void mul_one_identity(void) {
    secp256k1_fe a, one, r;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    one = FE_ONE;
    fe_mul(&r, &a, &one);
    ASSERT_TRUE(fe_hex_eq(&r, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530"));
}

/* ==================== Reduction Near P ==================== */

static void add_near_p(void) {
    secp256k1_fe pm1, one, r;
    fe_hex(&pm1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    one = FE_ONE;
    fe_add(&r, &pm1, &one);
    fe_normalize(&r);
    ASSERT_TRUE(fe_is_zero(&r));
}

static void add_near_p_overflow(void) {
    secp256k1_fe pm1, r;
    fe_hex(&pm1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    fe_add(&r, &pm1, &pm1);
    /* (p-1) + (p-1) = 2p-2 ≡ p-2 */
    ASSERT_TRUE(fe_hex_eq(&r, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d"));
}

static void sub_underflow(void) {
    secp256k1_fe zero, one, neg_one;
    zero = FE_ZERO;
    one = FE_ONE;
    fe_negate(&neg_one, &one, 1);
    fe_normalize(&neg_one);
    /* 0 - 1 ≡ p - 1 */
    ASSERT_TRUE(fe_hex_eq(&neg_one, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"));
}

/* ==================== Negation ==================== */

static void neg_twice_is_identity(void) {
    secp256k1_fe a, neg_a, neg_neg_a;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_negate(&neg_a, &a, 1);
    fe_negate(&neg_neg_a, &neg_a, 2);
    ASSERT_TRUE(fe_hex_eq(&neg_neg_a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530"));
}

static void add_neg_is_zero(void) {
    secp256k1_fe a, neg_a, r;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_negate(&neg_a, &a, 1);
    fe_add(&r, &a, &neg_a);
    fe_normalize(&r);
    ASSERT_TRUE(fe_is_zero(&r));
}

/* ==================== Multiplication ==================== */

static void mul_commutative(void) {
    secp256k1_fe a, b, ab, ba;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_hex(&b, "3982f19bef1615bccfbb05e321c10e1d4cba3df0e841c2e41eeb6016347653c3");
    fe_mul(&ab, &a, &b);
    fe_mul(&ba, &b, &a);
    ASSERT_TRUE(fe_equal(&ab, &ba));
}

static void sqr_matches_mul(void) {
    secp256k1_fe a, sqr_a, mul_aa;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_sqr(&sqr_a, &a);
    fe_mul(&mul_aa, &a, &a);
    ASSERT_TRUE(fe_equal(&sqr_a, &mul_aa));
}

static void mul_distributive(void) {
    /* a * (b + c) = a*b + a*c */
    secp256k1_fe a, b, c, bc, lhs, ab, ac, rhs;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_hex(&b, "3982f19bef1615bccfbb05e321c10e1d4cba3df0e841c2e41eeb6016347653c3");
    c = (secp256k1_fe){{7, 0, 0, 0}};
    fe_add(&bc, &b, &c);
    fe_mul(&lhs, &a, &bc);
    fe_mul(&ab, &a, &b);
    fe_mul(&ac, &a, &c);
    fe_add(&rhs, &ab, &ac);
    ASSERT_TRUE(fe_equal(&lhs, &rhs));
}

/* ==================== Inversion ==================== */

static void inv_mul_is_one(void) {
    secp256k1_fe a, a_inv, product;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_inv(&a_inv, &a);
    fe_mul(&product, &a, &a_inv);
    fe_normalize_full(&product);
    ASSERT_TRUE(fe_equal(&product, &FE_ONE));
}

static void inv_of_one(void) {
    secp256k1_fe r;
    fe_inv(&r, &FE_ONE);
    ASSERT_TRUE(fe_equal(&r, &FE_ONE));
}

static void inv_of_p_minus_1(void) {
    secp256k1_fe pm1, r;
    fe_hex(&pm1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    fe_inv(&r, &pm1);
    /* (p-1)^(-1) = p-1 because (p-1)^2 = 1 mod p */
    ASSERT_TRUE(fe_hex_eq(&r, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"));
}

/* ==================== Half ==================== */

static void half_of_even(void) {
    secp256k1_fe four = {{4, 0, 0, 0}}, r;
    fe_half(&r, &four);
    ASSERT_EQ_INT(r.d[0], 2);
    ASSERT_EQ_INT(r.d[1], 0);
}

static void half_then_double_roundtrips(void) {
    secp256k1_fe a, h, doubled;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_half(&h, &a);
    fe_add(&doubled, &h, &h);
    ASSERT_TRUE(fe_hex_eq(&doubled, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530"));
}

/* ==================== Square Root ==================== */

static void sqrt_of_square(void) {
    secp256k1_fe a, a_sq, root;
    fe_hex(&a, "67e56582298859ddae725f972992a07c6c4fb9f62a8fff58ce3ca926a1063530");
    fe_sqr(&a_sq, &a);
    ASSERT_TRUE(fe_sqrt(&root, &a_sq));
    /* root² should equal a² */
    secp256k1_fe root_sq;
    fe_sqr(&root_sq, &root);
    ASSERT_TRUE(fe_equal(&root_sq, &a_sq));
}

static void sqrt_of_non_residue(void) {
    /* 3 is not a quadratic residue mod p */
    secp256k1_fe three = {{3, 0, 0, 0}}, root;
    ASSERT_FALSE(fe_sqrt(&root, &three));
}

/* ==================== Carry-Fold Regression ==================== */

static void chained_lazy_add_then_mul(void) {
    /* 4*(p-1) ≡ p-4 (mod p) */
    secp256k1_fe pm1, two, four, one, product;
    fe_hex(&pm1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    fe_add(&two, &pm1, &pm1);
    fe_add(&four, &two, &two);
    one = FE_ONE;
    fe_mul(&product, &four, &one);
    fe_normalize_full(&product);
    ASSERT_TRUE(fe_hex_eq(&product, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2b"));
}

static void mul_of_large_values_stays_reduced(void) {
    /* ((p-1)^2)^2 ≡ 1 (mod p) */
    secp256k1_fe pm1, sq, sq_again;
    fe_hex(&pm1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    fe_sqr(&sq, &pm1);
    fe_mul(&sq_again, &sq, &sq);
    fe_normalize_full(&sq_again);
    ASSERT_TRUE(fe_equal(&sq_again, &FE_ONE));
}

static void repeated_squaring_converges(void) {
    /* Squaring chain: a, a², a⁴, …, a^(2^10) via mul and sqr must match */
    secp256k1_fe a;
    fe_hex(&a, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d");
    secp256k1_fe by_mul = a, by_sqr = a, tmp;
    for (int i = 0; i < 10; i++) {
        fe_mul(&tmp, &by_mul, &by_mul);
        by_mul = tmp;
    }
    for (int i = 0; i < 10; i++) {
        fe_sqr(&tmp, &by_sqr);
        by_sqr = tmp;
    }
    fe_normalize_full(&by_mul);
    fe_normalize_full(&by_sqr);
    ASSERT_TRUE(fe_equal(&by_mul, &by_sqr));
}

static void mul_roundtrip_via_inv(void) {
    secp256k1_fe pm1, lazy_big, b, ref, b_inv, back;
    fe_hex(&pm1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    fe_add(&lazy_big, &pm1, &pm1);
    b = (secp256k1_fe){{0x42, 0, 0, 0}};
    fe_mul(&ref, &lazy_big, &b);
    fe_inv(&b_inv, &b);
    fe_mul(&back, &ref, &b_inv);
    fe_normalize_full(&lazy_big);
    fe_normalize_full(&back);
    ASSERT_TRUE(fe_equal(&lazy_big, &back));
}

/* ==================== safegcd inversion against Fermat ==================== */

/* fe_inv (constant time) and fe_inv_var (variable time) are libsecp256k1's safegcd; they must
 * agree with the Fermat exponentiation, which they replaced, on every input. */
static void inv_matches_fermat(const secp256k1_fe *a) {
    secp256k1_fe want, got_ct, got_var;
    fe_inv_fermat(&want, a);
    fe_normalize_full(&want);
    fe_inv(&got_ct, a);
    fe_inv_var(&got_var, a);
    ASSERT_TRUE(fe_equal(&got_ct, &want));
    ASSERT_TRUE(fe_equal(&got_var, &want));
}

/* a * inv(a) == 1 for a non-zero a, multiplying by the reduced a. */
static void inv_is_inverse(const secp256k1_fe *a) {
    secp256k1_fe reduced = *a, inv, product;
    fe_normalize(&reduced);
    fe_inv(&inv, a);
    fe_mul(&product, &reduced, &inv);
    fe_normalize_full(&product);
    ASSERT_TRUE(fe_equal(&product, &FE_ONE));
    fe_inv_var(&inv, a);
    fe_mul(&product, &reduced, &inv);
    fe_normalize_full(&product);
    ASSERT_TRUE(fe_equal(&product, &FE_ONE));
}

static void safegcd_inv_edge_cases(void) {
    secp256k1_fe a;
    a = FE_ZERO; inv_matches_fermat(&a);                 /* 0 inverts to 0 */
    a = FE_ONE; inv_matches_fermat(&a);
    fe_hex(&a, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"); /* p - 1 */
    inv_matches_fermat(&a);
    fe_hex(&a, "0000000000000000000000000000000000000000000000000000000000000002");
    inv_matches_fermat(&a);
    /* Unnormalized: p + 1 and 2^256 - 1 (lazy results stay below 2^256 but may be >= p) */
    a.d[0] = 0xFFFFFFFEFFFFFC30ULL; a.d[1] = a.d[2] = a.d[3] = UINT64_MAX;
    inv_matches_fermat(&a);
    inv_is_inverse(&a);
    a.d[0] = a.d[1] = a.d[2] = a.d[3] = UINT64_MAX;
    inv_matches_fermat(&a);
    inv_is_inverse(&a);
    /* Every limb boundary of the signed62 conversion: single bits at 0, 61..63, 123..125, ... */
    static const int bits[] = {0, 61, 62, 63, 123, 124, 125, 127, 185, 186, 187, 191, 247, 248, 249, 255};
    for (size_t i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        a = FE_ZERO;
        a.d[bits[i] / 64] = 1ULL << (bits[i] % 64);
        inv_matches_fermat(&a);
    }
}

static void safegcd_inv_random(void) {
    /* xorshift64*: deterministic, so a failure reproduces */
    uint64_t s = 0x9E3779B97F4A7C15ULL;
    for (int n = 0; n < 2000; n++) {
        secp256k1_fe a;
        for (int i = 0; i < 4; i++) {
            s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
            a.d[i] = s * 0x2545F4914F6CDD1DULL;
        }
        inv_matches_fermat(&a);
        inv_is_inverse(&a);
    }
}

/* ==================== fe_mul / fe_sqr against a reference ==================== */

/* A slow reference that shares nothing with field.c: the full 512-bit product, then
 * lo + hi * C (2^256 = C mod p) folded until the high part is zero, then p subtracted
 * until the value is below p. */
#define REF_C 0x1000003D1ULL
static void fe_mul_ref(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe *b) {
    typedef unsigned __int128 u128;
    uint64_t w[8] = {0};
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 t = (u128)a->d[i] * b->d[j] + w[i + j] + carry;
            w[i + j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        w[i + 4] = carry;
    }
    uint64_t lo[4] = {w[0], w[1], w[2], w[3]}, hi[4] = {w[4], w[5], w[6], w[7]};
    for (;;) {
        u128 acc = 0;
        uint64_t t[5];
        for (int k = 0; k < 4; k++) {
            acc += (u128)lo[k] + (u128)hi[k] * REF_C;
            t[k] = (uint64_t)acc;
            acc >>= 64;
        }
        t[4] = (uint64_t)acc;
        for (int k = 0; k < 4; k++) lo[k] = t[k];
        hi[0] = t[4]; hi[1] = hi[2] = hi[3] = 0;
        if (t[4] == 0) break;
    }
    for (;;) { /* while lo >= p: lo -= p */
        int ge = lo[3] == UINT64_MAX && lo[2] == UINT64_MAX && lo[1] == UINT64_MAX &&
                 lo[0] >= 0xFFFFFFFEFFFFFC2FULL;
        if (!ge) break;
        lo[0] -= 0xFFFFFFFEFFFFFC2FULL; lo[1] = lo[2] = lo[3] = 0;
    }
    for (int k = 0; k < 4; k++) r->d[k] = lo[k];
}

static int mul_matches_ref(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe got, want;
    fe_mul(&got, a, b);
    fe_normalize_full(&got);
    fe_mul_ref(&want, a, b);
    return fe_equal(&got, &want);
}

static int sqr_matches_ref(const secp256k1_fe *a) {
    secp256k1_fe got, want;
    fe_sqr(&got, a);
    fe_normalize_full(&got);
    fe_mul_ref(&want, a, a);
    return fe_equal(&got, &want);
}

static void fe_set4(secp256k1_fe *r, uint64_t d3, uint64_t d2, uint64_t d1, uint64_t d0) {
    r->d[0] = d0; r->d[1] = d1; r->d[2] = d2; r->d[3] = d3;
}

/* Values at the edges of the 4x64 representation, reduced and unreduced (fe_add may leave a
 * result in [p, 2^256), and fe_mul must take it). */
static int edge_values(secp256k1_fe *v) {
    const uint64_t M = UINT64_MAX, P0 = 0xFFFFFFFEFFFFFC2FULL;
    int n = 0;
    fe_set4(&v[n++], 0, 0, 0, 0);
    fe_set4(&v[n++], 0, 0, 0, 1);
    fe_set4(&v[n++], 0, 0, 0, 2);
    fe_set4(&v[n++], 0, 0, 0, REF_C - 1);
    fe_set4(&v[n++], 0, 0, 0, REF_C);
    fe_set4(&v[n++], M, M, M, P0 - 2);      /* p - 2 */
    fe_set4(&v[n++], M, M, M, P0 - 1);      /* p - 1 */
    fe_set4(&v[n++], M, M, M, P0);          /* p (unreduced 0) */
    fe_set4(&v[n++], M, M, M, P0 + 1);      /* p + 1 */
    fe_set4(&v[n++], M, M, M, M - 0x1000);  /* just below 2^256 */
    fe_set4(&v[n++], M, M, M, M - 1);
    fe_set4(&v[n++], M, M, M, M);           /* 2^256 - 1 */
    fe_set4(&v[n++], 1ULL << 63, 0, 0, 0);  /* 2^255 */
    fe_set4(&v[n++], M, M, 0, 0);
    fe_set4(&v[n++], M, 0, 0, M);
    fe_set4(&v[n++], 0, M, M, M);
    fe_set4(&v[n++], M, M, M, 0);
    return n;
}

static void mul_edge_values_match_ref(void) {
    secp256k1_fe v[32];
    int n = edge_values(v);
    for (int i = 0; i < n; i++) {
        ASSERT_TRUE(sqr_matches_ref(&v[i]));
        for (int j = 0; j < n; j++) ASSERT_TRUE(mul_matches_ref(&v[i], &v[j]));
    }
}

static uint64_t xs64(uint64_t *s) {
    *s ^= *s >> 12; *s ^= *s << 25; *s ^= *s >> 27;
    return *s * 0x2545F4914F6CDD1DULL;
}

/* Random inputs near 2^256 (top limbs all ones), in [p, 2^256), and anywhere. */
static void mul_random_values_match_ref(void) {
    uint64_t s = 0xD1B54A32D192ED03ULL;
    for (int n = 0; n < 200000; n++) {
        secp256k1_fe a, b;
        for (int k = 0; k < 4; k++) { a.d[k] = xs64(&s); b.d[k] = xs64(&s); }
        switch (n % 4) {
        case 0: a.d[1] = a.d[2] = a.d[3] = UINT64_MAX; break;                        /* a near 2^256 */
        case 1: a.d[1] = a.d[2] = a.d[3] = b.d[1] = b.d[2] = b.d[3] = UINT64_MAX; break;
        case 2: a.d[1] = a.d[2] = a.d[3] = UINT64_MAX; a.d[0] |= 0xFFFFFFFEFFFFFC2FULL; break; /* >= p */
        default: break;
        }
        ASSERT_TRUE(mul_matches_ref(&a, &b));
        ASSERT_TRUE(sqr_matches_ref(&a));
    }
}

/* a mod p, for any 4x64 value (reduced or in [p, 2^256)). */
static void fe_reduce_ref(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe one;
    fe_set4(&one, 0, 0, 0, 1);
    fe_mul_ref(r, a, &one);
}

/* fe_negate: -a mod p for every representable a, and the result a valid element (<= p). */
static int neg_matches_ref(const secp256k1_fe *a) {
    secp256k1_fe got, ar, sum, sumr, zero;
    fe_negate(&got, a, 1);
    if (fe_cmp(&got, &FE_P) > 0) return 0;
    fe_reduce_ref(&ar, a);
    fe_reduce_ref(&sumr, &got);
    /* (a mod p) + (-a mod p) is 0 or p */
    fe_add(&sum, &ar, &sumr);
    fe_set4(&zero, 0, 0, 0, 0);
    fe_reduce_ref(&sum, &sum);
    return fe_equal(&sum, &zero);
}

/* fe_add: (a + b) mod p for every pair of representable values. */
static int add_matches_ref(const secp256k1_fe *a, const secp256k1_fe *b) {
    typedef unsigned __int128 u128;
    secp256k1_fe got, want, gotr;
    fe_add(&got, a, b);
    /* want = ((a mod p) + (b mod p)) mod p, without fe_add */
    secp256k1_fe ar, br;
    fe_reduce_ref(&ar, a);
    fe_reduce_ref(&br, b);
    u128 acc = 0;
    for (int k = 0; k < 4; k++) {
        acc += (u128)ar.d[k] + br.d[k];
        want.d[k] = (uint64_t)acc;
        acc >>= 64;
    }
    if (acc) { /* 2^256 = C mod p; the sum is below 2p, so no second carry */
        acc = (u128)want.d[0] + REF_C;
        want.d[0] = (uint64_t)acc; acc >>= 64;
        for (int k = 1; k < 4 && acc; k++) { acc += want.d[k]; want.d[k] = (uint64_t)acc; acc >>= 64; }
    }
    fe_reduce_ref(&want, &want);
    fe_reduce_ref(&gotr, &got);
    return fe_equal(&gotr, &want);
}

static void neg_add_edge_values_match_ref(void) {
    secp256k1_fe v[32];
    int n = edge_values(v);
    for (int i = 0; i < n; i++) {
        ASSERT_TRUE(neg_matches_ref(&v[i]));
        for (int j = 0; j < n; j++) ASSERT_TRUE(add_matches_ref(&v[i], &v[j]));
    }
}

static void neg_add_random_values_match_ref(void) {
    uint64_t s = 0x9E3779B97F4A7C15ULL;
    for (int n = 0; n < 200000; n++) {
        secp256k1_fe a, b;
        for (int k = 0; k < 4; k++) { a.d[k] = xs64(&s); b.d[k] = xs64(&s); }
        switch (n % 4) {
        case 0: a.d[1] = a.d[2] = a.d[3] = UINT64_MAX; break;
        case 1: a.d[1] = a.d[2] = a.d[3] = b.d[1] = b.d[2] = b.d[3] = UINT64_MAX; break;
        case 2: a.d[1] = a.d[2] = a.d[3] = UINT64_MAX; a.d[0] |= 0xFFFFFFFEFFFFFC2FULL; break;
        default: break;
        }
        ASSERT_TRUE(neg_matches_ref(&a));
        ASSERT_TRUE(add_matches_ref(&a, &b));
    }
}

/* ==================== Runner ==================== */

void run_field_tests(void) {
    SUITE(field);
    printf("Running field arithmetic tests...\n");
    /* Identities */
    TEST(add_zero_identity);
    TEST(sub_self_is_zero);
    TEST(add_then_sub_roundtrips);
    TEST(mul_one_identity);
    /* Reduction */
    TEST(add_near_p);
    TEST(add_near_p_overflow);
    TEST(sub_underflow);
    /* Negation */
    TEST(neg_twice_is_identity);
    TEST(add_neg_is_zero);
    TEST(neg_add_edge_values_match_ref);
    TEST(neg_add_random_values_match_ref);
    /* Multiplication */
    TEST(mul_commutative);
    TEST(sqr_matches_mul);
    TEST(mul_distributive);
    TEST(mul_edge_values_match_ref);
    TEST(mul_random_values_match_ref);
    /* Inversion */
    TEST(inv_mul_is_one);
    TEST(inv_of_one);
    TEST(inv_of_p_minus_1);
    TEST(safegcd_inv_edge_cases);
    TEST(safegcd_inv_random);
    /* Half */
    TEST(half_of_even);
    TEST(half_then_double_roundtrips);
    /* Sqrt */
    TEST(sqrt_of_square);
    TEST(sqrt_of_non_residue);
    /* Carry-fold regression */
    TEST(chained_lazy_add_then_mul);
    TEST(mul_of_large_values_stays_reduced);
    TEST(repeated_squaring_converges);
    TEST(mul_roundtrip_via_inv);
    printf("  Field: done\n");
}
