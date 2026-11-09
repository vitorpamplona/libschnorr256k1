/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Point operations on secp256k1 with comb, GLV+wNAF, Strauss/Shamir.
 */
#include "point.h"
#include <string.h>
#include <stdlib.h>

/* ==================== Generator Point ==================== */

/* G_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 */
/* G_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 */
/* 4x64 little-endian */
const secp256k1_ge SECP256K1_G = {
    .x = {{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
            0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}},
    .y = {{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
            0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}}
};

/* GLV beta: cube root of unity mod p (4x64 little-endian) */
/* beta = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE */
static const secp256k1_fe GLV_BETA = {{
    0xC1396C28719501EEULL, 0x9CF0497512F58995ULL,
    0x6E64479EAC3434E9ULL, 0x7AE96A2B657C0710ULL
}};

/* Curve constant b = 7 */
static const secp256k1_fe FE_SEVEN = {{7, 0, 0, 0}};

/* ==================== Precomputed Tables ==================== */

#define COMB_BLOCKS 11
#define COMB_TEETH  6
#define COMB_SPACING 4
#define COMB_POINTS (1 << COMB_TEETH) /* 64 */
#define COMB_TABLE_SIZE (COMB_BLOCKS * COMB_POINTS) /* 704 */

#define WINDOW_G 12
#define G_TABLE_SIZE (1 << (WINDOW_G - 2)) /* 1024 */

static secp256k1_ge comb_table[COMB_TABLE_SIZE];
static secp256k1_ge g_odd_table[G_TABLE_SIZE];
static secp256k1_ge g_lam_table[G_TABLE_SIZE];

/* ==================== P-side wNAF Table Cache ==================== */
/*
 * Cache P-side affine wNAF tables keyed by pubkey x-coordinate.
 * In Nostr, the same pubkeys are verified repeatedly (feed from one author).
 * Building the P-side table costs ~437 field ops (~27% of verify). Caching
 * skips this entirely on repeat verifications.
 *
 * An x is shared by two points, P and -P, and ecmult (tweak-mul, ECDH) takes either. An entry
 * holds the tables of the point it was built from, with that point's y parity: the tables of
 * -P are the same points negated (lambda(-P) = -lambda(P) too), so a lookup for the other
 * point returns them with flip set, and the caller negates every digit. Keyed by x alone, a
 * tweak-mul of the odd-y point left tables that verify then used for its even-y x-only key,
 * and rejected valid signatures (libschnorr256k1-bench's KI-3).
 *
 * Threads share the cache. Each slot has a lock, held only to copy an entry in or out (the
 * tables are built outside it), and a thread that cannot take it within a few tries builds
 * its own tables: no one waits on another's work, and no reader can see a key with the tables
 * of another (a forged signature verified against a key while another thread rewrote its slot
 * for a colliding key, before the lock).
 *
 * 1024 entries × 16 AffinePoints × 64 bytes ≈ 1MB. Acceptable for mobile.
 */
#define P_TABLE_CACHE_SIZE 1024
#define P_TABLE_CACHE_MASK (P_TABLE_CACHE_SIZE - 1)
#define P_TABLE_ENTRIES 8 /* 2^(wP-2) for wP=5 */

typedef struct {
    secp256k1_ge p_odd[P_TABLE_ENTRIES];      /* affine odd-multiples of P */
    secp256k1_ge p_lam_odd[P_TABLE_ENTRIES];  /* affine odd-multiples of lambda(P) */
} p_table_set;

typedef struct {
    secp256k1_fe px;                          /* cache key: x-coordinate */
    p_table_set tables;
    int y_odd;                                /* parity of the y the tables were built for */
    int valid;
    slot_lock lock;
} cached_p_table;

static cached_p_table p_table_cache[P_TABLE_CACHE_SIZE];

static int p_cache_slot(const secp256k1_fe *px) {
    return ((int)(px->d[0] ^ (px->d[1] << 3))) & P_TABLE_CACHE_MASK;
}

/* The wNAF-5 tables of affine P (on the curve) and lambda(P), copied from the cache or built
 * (and offered to it), into out. *flip is 1 when they are the tables of -P: the caller negates
 * each point it takes from them. */
static void p_tables(p_table_set *out, const secp256k1_ge *p, int *flip) {
    cached_p_table *cached = &p_table_cache[p_cache_slot(&p->x)];
    const int y_odd = fe_is_odd(&p->y);

    if (slot_lock_acquire(&cached->lock)) {
        int hit = cached->valid && fe_equal(&cached->px, &p->x);
        if (hit) {
            /* Same x on the curve: p is the cached point or its negation */
            *out = cached->tables;
            *flip = y_odd != cached->y_odd;
        }
        slot_lock_release(&cached->lock);
        if (hit) return;
    }

    /* P, 3P, ..., 15P with mixed additions and one inversion (ecmult_odd_multiples_affine), and
     * lambda(kP) = (beta*x, y) from them: no second table, no second inversion. */
    secp256k1_gej scratch[P_TABLE_ENTRIES];
    ecmult_odd_multiples_affine(out->p_odd, p, 1, P_TABLE_ENTRIES, scratch);
    for (int i = 0; i < P_TABLE_ENTRIES; i++) {
        fe_mul(&out->p_lam_odd[i].x, &out->p_odd[i].x, &GLV_BETA);
        fe_normalize_full(&out->p_lam_odd[i].x);
        out->p_lam_odd[i].y = out->p_odd[i].y;
    }
    *flip = 0;

    if (slot_lock_acquire(&cached->lock)) {
        cached->px = p->x;
        fe_normalize(&cached->px);
        cached->tables = *out;
        cached->y_odd = y_odd;
        cached->valid = 1;
        slot_lock_release(&cached->lock);
    }
}

/* ==================== Point Operations ==================== */

void gej_set_infinity(secp256k1_gej *r) {
    r->x = FE_ZERO;
    r->y = FE_ONE;
    r->z = FE_ZERO;
    r->infinity = 1;
}

void gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a) {
    r->x = a->x;
    r->y = a->y;
    r->z = FE_ONE;
    r->infinity = 0;
}

int gej_is_infinity(const secp256k1_gej *r) {
    return r->infinity;
}

/* Point doubling: r = 2*p (3M + 4S) using a=0 formula from libsecp256k1 */
void gej_double(secp256k1_gej *r, const secp256k1_gej *p) {
    /* Every coordinate goes to a local and r is written last, so r may be p (no copy). Lazy:
     * the results are below 2^256, not normalized; everything downstream takes that. */
    if (p->infinity) {
        gej_set_infinity(r);
        return;
    }
    secp256k1_fe s, l, l3, t, x3, u, s2, z3;

    fe_sqr(&s, &p->y);         /* S = Y^2 */
    fe_sqr(&l, &p->x);
    fe_add(&l3, &l, &l);
    fe_add(&l3, &l3, &l);
    fe_half(&l, &l3);          /* L = (3/2) X^2 */
    fe_mul(&t, &p->x, &s);     /* T = X*S */

    fe_sqr(&x3, &l);
    fe_sub(&x3, &x3, &t);
    fe_sub(&x3, &x3, &t);      /* X3 = L^2 - 2T */

    fe_sub(&u, &t, &x3);
    fe_mul(&u, &l, &u);
    fe_sqr(&s2, &s);           /* Y3 = L*(T - X3) - S^2 */

    fe_mul(&z3, &p->y, &p->z); /* Z3 = Y*Z */

    r->x = x3;
    fe_sub(&r->y, &u, &s2);
    r->z = z3;
    r->infinity = 0;
}

/* Mixed addition: r = p + q where q is affine (Z=1). 8M + 3S. r may be p. */
void gej_add_ge(secp256k1_gej *r, const secp256k1_gej *p, const secp256k1_ge *q) {
    /* r is written last, so r may be p (no copy). Lazy results, as gej_double. */
    if (p->infinity) {
        gej_set_ge(r, q);
        return;
    }
    secp256k1_fe z12, z13, u2, s2, h, h2, i, j, rr, v, x3, y3, z3, t;

    fe_sqr(&z12, &p->z);
    fe_mul(&z13, &z12, &p->z);
    fe_mul(&u2, &q->x, &z12);      /* U2 = qx*Z1^2 */
    fe_mul(&s2, &q->y, &z13);      /* S2 = qy*Z1^3 */

    fe_sub(&h, &u2, &p->x);        /* H = U2 - X1 */
    fe_sub(&rr, &s2, &p->y);       /* S2 - Y1 */
    if (fe_is_zero(&h)) {
        if (fe_is_zero(&rr)) { gej_double(r, p); }
        else { gej_set_infinity(r); }
        return;
    }

    fe_add(&h2, &h, &h);
    fe_sqr(&i, &h2);               /* I = (2H)^2 */
    fe_mul(&j, &h, &i);            /* J = H*I */
    fe_add(&rr, &rr, &rr);         /* r = 2*(S2 - Y1) */
    fe_mul(&v, &p->x, &i);         /* V = X1*I */

    fe_sqr(&x3, &rr);
    fe_sub(&x3, &x3, &j);
    fe_sub(&x3, &x3, &v);
    fe_sub(&x3, &x3, &v);          /* X3 = r^2 - J - 2V */

    fe_sub(&t, &v, &x3);
    fe_mul(&y3, &rr, &t);
    fe_mul(&t, &p->y, &j);
    fe_add(&t, &t, &t);
    fe_sub(&y3, &y3, &t);          /* Y3 = r*(V - X3) - 2*Y1*J */

    fe_mul(&z3, &p->z, &h);
    fe_add(&z3, &z3, &z3);         /* Z3 = 2*Z1*H */

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->infinity = 0;
}

/* Full Jacobian addition: r = p + q (11M + 5S) */
void gej_add(secp256k1_gej *r, const secp256k1_gej *p, const secp256k1_gej *q) {
    /* r is written last, so r may be p or q (no copy). Lazy results, as gej_double. */
    if (p->infinity) { *r = *q; return; }
    if (q->infinity) { *r = *p; return; }
    secp256k1_fe z12, z22, z13, z23, u1, u2, s1, s2, h, h2, i, j, rr, v, x3, y3, z3, t;

    fe_sqr(&z12, &p->z);
    fe_sqr(&z22, &q->z);
    fe_mul(&u1, &p->x, &z22);
    fe_mul(&u2, &q->x, &z12);
    fe_mul(&z23, &z22, &q->z);
    fe_mul(&z13, &z12, &p->z);
    fe_mul(&s1, &p->y, &z23);
    fe_mul(&s2, &q->y, &z13);

    fe_sub(&h, &u2, &u1);
    fe_sub(&rr, &s2, &s1);
    if (fe_is_zero(&h)) {
        if (fe_is_zero(&rr)) { gej_double(r, p); }
        else { gej_set_infinity(r); }
        return;
    }

    fe_add(&h2, &h, &h);
    fe_sqr(&i, &h2);               /* I = (2H)^2 */
    fe_mul(&j, &h, &i);            /* J = H*I */
    fe_add(&rr, &rr, &rr);         /* r = 2*(S2 - S1) */
    fe_mul(&v, &u1, &i);           /* V = U1*I */

    fe_sqr(&x3, &rr);
    fe_sub(&x3, &x3, &j);
    fe_sub(&x3, &x3, &v);
    fe_sub(&x3, &x3, &v);          /* X3 = r^2 - J - 2V */

    fe_sub(&t, &v, &x3);
    fe_mul(&y3, &rr, &t);
    fe_mul(&t, &s1, &j);
    fe_add(&t, &t, &t);
    fe_sub(&y3, &y3, &t);          /* Y3 = r*(V - X3) - 2*S1*J */

    fe_add(&z3, &p->z, &q->z);
    fe_sqr(&z3, &z3);
    fe_sub(&z3, &z3, &z12);
    fe_sub(&z3, &z3, &z22);
    fe_mul(&z3, &z3, &h);          /* Z3 = ((Z1 + Z2)^2 - Z1^2 - Z2^2)*H = 2*Z1*Z2*H */

    r->x = x3;
    r->y = y3;
    r->z = z3;
    r->infinity = 0;
}

/* Convert Jacobian to affine */
int gej_to_ge(secp256k1_ge *r, const secp256k1_gej *p) {
    secp256k1_fe zi, zi2, zi3;
    if (p->infinity) return 0;

    fe_inv(&zi, &p->z);
    fe_sqr(&zi2, &zi);
    fe_mul(&zi3, &zi2, &zi);
    fe_mul(&r->x, &p->x, &zi2);
    fe_mul(&r->y, &p->y, &zi3);
    fe_normalize_full(&r->x);
    fe_normalize_full(&r->y);
    return 1;
}

/* gej_to_ge with a variable-time inversion: only for points that are public (verification). */
int gej_to_ge_var(secp256k1_ge *r, const secp256k1_gej *p) {
    secp256k1_fe zi, zi2, zi3;
    if (p->infinity) return 0;

    fe_inv_var(&zi, &p->z);
    fe_sqr(&zi2, &zi);
    fe_mul(&zi3, &zi2, &zi);
    fe_mul(&r->x, &p->x, &zi2);
    fe_mul(&r->y, &p->y, &zi3);
    fe_normalize_full(&r->x);
    fe_normalize_full(&r->y);
    return 1;
}

int gej_to_ge_x(secp256k1_fe *rx, const secp256k1_gej *p) {
    secp256k1_fe zi, zi2;
    if (p->infinity) return 0;

    fe_inv(&zi, &p->z);
    fe_sqr(&zi2, &zi);
    fe_mul(rx, &p->x, &zi2);
    fe_normalize_full(rx);
    return 1;
}

/* ==================== Key/Point Codec ==================== */

int point_lift_x(secp256k1_fe *out_x, secp256k1_fe *out_y, const secp256k1_fe *x) {
    secp256k1_fe x2, x3, c;

    /* y^2 = x^3 + 7 */
    fe_sqr(&x2, x);
    fe_mul(&x3, &x2, x);
    fe_add(&c, &x3, &FE_SEVEN);
    fe_normalize(&c);

    if (!fe_sqrt(out_y, &c)) return 0;
    fe_normalize_full(out_y);

    /* Ensure even y */
    if (fe_is_odd(out_y)) {
        fe_negate(out_y, out_y, 1);
        fe_normalize_full(out_y);
    }

    *out_x = *x;
    return 1;
}

/* A 33-byte compressed (02/03) or 65-byte uncompressed (04) key: coordinates below p and the
 * point on the curve, or 0. Unchecked, an off-curve point reached the shared table cache under a
 * real key's x (every valid signature by that key then failed) and gave invalid-curve results
 * for secret tweaks. */
int point_parse_pubkey(secp256k1_ge *r, const uint8_t *pubkey, size_t len) {
    secp256k1_fe x;

    if (len == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)) {
        fe_from_bytes(&x, pubkey + 1);
        if (fe_cmp(&x, &FE_P) >= 0) return 0;
        secp256k1_fe y;
        if (!point_lift_x(&r->x, &y, &x)) return 0;
        r->y = y;
        /* If prefix is 03 (odd y), negate */
        if (pubkey[0] == 0x03 && !fe_is_odd(&r->y)) {
            fe_negate(&r->y, &r->y, 1);
            fe_normalize_full(&r->y);
        } else if (pubkey[0] == 0x02 && fe_is_odd(&r->y)) {
            fe_negate(&r->y, &r->y, 1);
            fe_normalize_full(&r->y);
        }
        return 1;
    } else if (len == 65 && pubkey[0] == 0x04) {
        fe_from_bytes(&r->x, pubkey + 1);
        fe_from_bytes(&r->y, pubkey + 33);
        if (fe_cmp(&r->x, &FE_P) >= 0 || fe_cmp(&r->y, &FE_P) >= 0) return 0;
        /* y^2 == x^3 + 7 */
        secp256k1_fe y2, x3;
        static const secp256k1_fe SEVEN = {{7, 0, 0, 0}};
        fe_sqr(&y2, &r->y);
        fe_sqr(&x3, &r->x);
        fe_mul(&x3, &x3, &r->x);
        fe_add(&x3, &x3, &SEVEN);
        return fe_equal(&y2, &x3);
    }
    return 0;
}

void point_serialize_uncompressed(uint8_t *out65, const secp256k1_ge *p) {
    out65[0] = 0x04;
    fe_to_bytes(out65 + 1, &p->x);
    fe_to_bytes(out65 + 33, &p->y);
}

void point_serialize_compressed(uint8_t *out33, const secp256k1_ge *p) {
    out33[0] = fe_is_odd(&p->y) ? 0x03 : 0x02;
    fe_to_bytes(out33 + 1, &p->x);
}

int point_has_even_y(const secp256k1_fe *y) {
    return !fe_is_odd(y);
}

/* ==================== Batch to Affine (Montgomery's Trick) ==================== */

void batch_to_affine(secp256k1_ge *out, const secp256k1_gej *in, int count) {
    if (count == 0) return;

    secp256k1_fe *cumz = (secp256k1_fe *)malloc((size_t)count * sizeof(secp256k1_fe));
    if (!cumz) return;

    /* Build cumulative Z products, skipping infinity points (Z=0).
     * For infinity points, carry forward the previous cumulative product. */
    int first_valid = -1;
    for (int i = 0; i < count; i++) {
        if (in[i].infinity) {
            /* Infinity: carry previous product (or set to 1 if first) */
            if (i == 0) {
                cumz[0] = FE_ONE;
            } else {
                cumz[i] = cumz[i-1];
            }
            out[i] = (secp256k1_ge){ .x = FE_ZERO, .y = FE_ZERO };
        } else {
            if (first_valid < 0) first_valid = i;
            if (i == 0 || first_valid == i) {
                cumz[i] = in[i].z;
            } else {
                fe_mul(&cumz[i], &cumz[i-1], &in[i].z);
            }
        }
    }

    if (first_valid < 0) { free(cumz); return; } /* All infinity */

    secp256k1_fe inv, zi, zi2, zi3;
    /* Variable time: every caller converts a table of public points (the generator's, or the
     * odd multiples of a public key or a public point being multiplied). */
    fe_inv_var(&inv, &cumz[count-1]);

    for (int i = count - 1; i >= 1; i--) {
        if (in[i].infinity) continue; /* Skip, already set to zero */
        fe_mul(&zi, &inv, &cumz[i-1]);
        fe_mul(&inv, &inv, &in[i].z);
        fe_sqr(&zi2, &zi);
        fe_mul(&zi3, &zi2, &zi);
        fe_mul(&out[i].x, &in[i].x, &zi2);
        fe_mul(&out[i].y, &in[i].y, &zi3);
        fe_normalize_full(&out[i].x);
        fe_normalize_full(&out[i].y);
    }
    /* i=0 */
    if (!in[0].infinity) {
        fe_sqr(&zi2, &inv);
        fe_mul(&zi3, &zi2, &inv);
        fe_mul(&out[0].x, &in[0].x, &zi2);
        fe_mul(&out[0].y, &in[0].y, &zi3);
        fe_normalize_full(&out[0].x);
        fe_normalize_full(&out[0].y);
    }

    free(cumz);
}

/* ==================== Table Initialization ==================== */

void ecmult_odd_multiples_affine(secp256k1_ge *out, const secp256k1_ge *pts, int count, int T,
                                 secp256k1_gej *jac) {
    const int n = count * T;
    if (count <= 0) return;

    for (int j = 0; j < count; j++) {
        /* D = 2Q = (X, Y, Z). On the isomorphic curve y^2 = x^3 + 7*Z^6, the map
         * (x, y) -> (x*Z^2, y*Z^3) sends D to the affine (X, Y) and Q to (x*Z^2, y*Z^3, 1), so
         * each odd multiple is one mixed addition there. The addition formulas don't use the
         * curve constant, and a point (X', Y', Z') there is (X', Y', Z'*Z) on secp256k1. */
        secp256k1_gej q, d;
        gej_set_ge(&q, &pts[j]);
        gej_double(&d, &q);
        secp256k1_ge d_iso = { .x = d.x, .y = d.y };
        secp256k1_fe z2, z3;
        fe_sqr(&z2, &d.z);
        fe_mul(&z3, &z2, &d.z);
        secp256k1_gej *t = &jac[j * T];
        fe_mul(&t[0].x, &pts[j].x, &z2);
        fe_mul(&t[0].y, &pts[j].y, &z3);
        t[0].z = FE_ONE;
        t[0].infinity = 0;
        for (int k = 1; k < T; k++) gej_add_ge(&t[k], &t[k - 1], &d_iso);
        for (int k = 0; k < T; k++) fe_mul(&t[k].z, &t[k].z, &d.z);
    }

    /* Montgomery's trick, the running products of the Z's kept in out[i].x until out[i] is
     * written (backwards, so out[i - 1].x still holds its product when out[i] needs it). Odd
     * multiples kQ with k < 2T of a point of prime order n are never infinity. */
    out[0].x = jac[0].z;
    for (int i = 1; i < n; i++) fe_mul(&out[i].x, &out[i - 1].x, &jac[i].z);
    secp256k1_fe inv, zi, zi2, zi3;
    fe_inv_var(&inv, &out[n - 1].x);
    for (int i = n - 1; i >= 0; i--) {
        if (i > 0) {
            fe_mul(&zi, &inv, &out[i - 1].x);
            fe_mul(&inv, &inv, &jac[i].z);
        } else {
            zi = inv;
        }
        fe_sqr(&zi2, &zi);
        fe_mul(&zi3, &zi2, &zi);
        fe_mul(&out[i].x, &jac[i].x, &zi2);
        fe_mul(&out[i].y, &jac[i].y, &zi3);
        fe_normalize_full(&out[i].x);
        fe_normalize_full(&out[i].y);
    }
}

static void build_g_odd_table(void) {
    secp256k1_gej g, g2;
    gej_set_ge(&g, &SECP256K1_G);
    gej_double(&g2, &g);

    secp256k1_gej *jac = (secp256k1_gej *)malloc(G_TABLE_SIZE * sizeof(secp256k1_gej));
    if (!jac) return;

    jac[0] = g;
    for (int i = 1; i < G_TABLE_SIZE; i++) {
        gej_add(&jac[i], &jac[i-1], &g2);
    }

    batch_to_affine(g_odd_table, jac, G_TABLE_SIZE);

    /* Build lambda(G) table: lambda((x,y)) = (beta*x, y) */
    for (int i = 0; i < G_TABLE_SIZE; i++) {
        fe_mul(&g_lam_table[i].x, &g_odd_table[i].x, &GLV_BETA);
        fe_normalize_full(&g_lam_table[i].x);
        g_lam_table[i].y = g_odd_table[i].y;
    }

    free(jac);
}

static void build_comb_table(void) {
    int num_teeth = COMB_BLOCKS * COMB_TEETH;

    secp256k1_gej *tooth_g = (secp256k1_gej *)malloc((size_t)num_teeth * sizeof(secp256k1_gej));
    if (!tooth_g) return;

    gej_set_ge(&tooth_g[0], &SECP256K1_G);
    for (int i = 1; i < num_teeth; i++) {
        tooth_g[i] = tooth_g[i-1];
        for (int j = 0; j < COMB_SPACING; j++) {
            gej_double(&tooth_g[i], &tooth_g[i]);
        }
    }

    /* Convert tooth points to affine for efficient mixed addition */
    secp256k1_ge *tooth_aff = (secp256k1_ge *)malloc((size_t)num_teeth * sizeof(secp256k1_ge));
    if (!tooth_aff) { free(tooth_g); return; }
    batch_to_affine(tooth_aff, tooth_g, num_teeth);

    /* Build all 2^TEETH combinations per block */
    secp256k1_gej *jac = (secp256k1_gej *)malloc(COMB_TABLE_SIZE * sizeof(secp256k1_gej));
    if (!jac) { free(tooth_g); free(tooth_aff); return; }

    for (int b = 0; b < COMB_BLOCKS; b++) {
        int base = b * COMB_POINTS;
        gej_set_infinity(&jac[base]); /* index 0 = infinity */
        for (int m = 1; m < COMB_POINTS; m++) {
            int changed_bit = __builtin_ctz(m);
            if ((m & (m - 1)) == 0) {
                /* Power of 2: just the tooth point */
                gej_set_ge(&jac[base + m], &tooth_aff[b * COMB_TEETH + changed_bit]);
            } else {
                int prev = m ^ (1 << changed_bit);
                gej_add_ge(&jac[base + m], &jac[base + prev],
                           &tooth_aff[b * COMB_TEETH + changed_bit]);
            }
        }
    }

    batch_to_affine(comb_table, jac, COMB_TABLE_SIZE);

    free(jac);
    free(tooth_aff);
    free(tooth_g);
}

/* Called once, by secp256k1c_init. */
void ecmult_tables_init(void) {
    build_g_odd_table();
    build_comb_table();
}

/* ==================== Scalar Multiplication ==================== */

/* Helper: test bit n in a scalar */
static inline int scalar_test_bit(const secp256k1_scalar *s, int bit) {
    return (int)((s->d[bit >> 6] >> (bit & 63)) & 1);
}

/* G multiplication using comb method: only 3 doublings + ~43 table lookups.
 * ~2.2x faster than GLV+wNAF (~130 doublings + ~32 additions). */
void ecmult_gen(secp256k1_gej *r, const secp256k1_scalar *scalar) {
    if (scalar_is_zero(scalar)) {
        gej_set_infinity(r);
        return;
    }

    const secp256k1_ge *table = comb_table;
    gej_set_infinity(r);

    for (int comb_off = COMB_SPACING - 1; comb_off >= 0; comb_off--) {
        if (comb_off < COMB_SPACING - 1) {
            secp256k1_gej tmp;
            gej_double(&tmp, r);
            *r = tmp;
        }
        for (int block = 0; block < COMB_BLOCKS; block++) {
            int mask = 0;
            for (int tooth = 0; tooth < COMB_TEETH; tooth++) {
                int bit_pos = (block * COMB_TEETH + tooth) * COMB_SPACING + comb_off;
                if (bit_pos < 256 && scalar_test_bit(scalar, bit_pos)) {
                    mask |= (1 << tooth);
                }
            }
            if (mask != 0) {
                const secp256k1_ge *entry = &table[block * COMB_POINTS + mask];
                secp256k1_gej tmp;
                gej_add_ge(&tmp, r, entry);
                *r = tmp;
            }
        }
    }
}

/* Arbitrary point multiplication using GLV + wNAF-5 */
void ecmult(secp256k1_gej *r, const secp256k1_ge *p, const secp256k1_scalar *scalar) {
    if (scalar_is_zero(scalar)) {
        gej_set_infinity(r);
        return;
    }

    int w = 5;

    /* GLV split */
    glv_split split;
    glv_split_scalar(&split, scalar);

    /* wNAF encode */
    int wnaf1[145], wnaf2[145];
    memset(wnaf1, 0, sizeof(wnaf1));
    memset(wnaf2, 0, sizeof(wnaf2));
    int len1 = wnaf_encode(wnaf1, 145, &split.k1, w);
    int len2 = wnaf_encode(wnaf2, 145, &split.k2, w);

    /* P-side tables: from the cache shared with ecmult_double_g.
     * For ECDH, the same peer key is used repeatedly (NIP-44 conversations). */
    int flip;
    p_table_set tables;
    p_tables(&tables, p, &flip);
    const secp256k1_ge *p_odd = tables.p_odd;
    const secp256k1_ge *p_lam_odd = tables.p_lam_odd;
    split.neg_k1 ^= flip;
    split.neg_k2 ^= flip;

    /* Find highest non-zero digit */
    int bits = (len1 > len2) ? len1 : len2;
    if (bits == 0) bits = 1;

    gej_set_infinity(r);

    for (int i = bits - 1; i >= 0; i--) {
        gej_double(r, r);

        int d;

        /* Stream 1: k1 * P */
        d = (i < 145) ? wnaf1[i] : 0;
        if (d != 0) {
            int idx = (d > 0 ? d : -d) / 2;
            secp256k1_ge pt = p_odd[idx];
            if ((d < 0) ^ split.neg_k1) {
                fe_negate(&pt.y, &pt.y, 1);
            }
            gej_add_ge(r, r, &pt);
        }

        /* Stream 2: k2 * lambda(P) */
        d = (i < 145) ? wnaf2[i] : 0;
        if (d != 0) {
            int idx = (d > 0 ? d : -d) / 2;
            secp256k1_ge pt = p_lam_odd[idx];
            if ((d < 0) ^ split.neg_k2) {
                fe_negate(&pt.y, &pt.y, 1);
            }
            gej_add_ge(r, r, &pt);
        }
    }
}

/* Dual scalar multiplication: r = s*G + e*P (Strauss + GLV) */
void ecmult_double_g(secp256k1_gej *r, const secp256k1_scalar *s_scalar,
                     const secp256k1_ge *p, const secp256k1_scalar *e_scalar) {
    ecmult_double_g_multi(r, s_scalar, p, e_scalar, NULL, NULL, 0, NULL, 0);
}

void ecmult_double_g_multi(secp256k1_gej *r, const secp256k1_scalar *s_scalar,
                           const secp256k1_ge *p, const secp256k1_scalar *e_scalar,
                           const secp256k1_ge *q_tables, const int8_t *q_wnaf, int q_stride,
                           const int *q_len, int q_count) {
    int wP = 5;

    /* GLV split both scalars */
    glv_split s_split, e_split;
    glv_split_scalar(&s_split, s_scalar);
    glv_split_scalar(&e_split, e_scalar);

    /* wNAF encode all 4 half-scalars */
    int wnaf_s1[145], wnaf_s2[145], wnaf_e1[145], wnaf_e2[145];
    memset(wnaf_s1, 0, sizeof(wnaf_s1));
    memset(wnaf_s2, 0, sizeof(wnaf_s2));
    memset(wnaf_e1, 0, sizeof(wnaf_e1));
    memset(wnaf_e2, 0, sizeof(wnaf_e2));
    wnaf_encode(wnaf_s1, 145, &s_split.k1, WINDOW_G);
    wnaf_encode(wnaf_s2, 145, &s_split.k2, WINDOW_G);
    wnaf_encode(wnaf_e1, 145, &e_split.k1, wP);
    wnaf_encode(wnaf_e2, 145, &e_split.k2, wP);

    /* P-side tables: from the cache, built only on a miss */
    int flip;
    p_table_set tables;
    p_tables(&tables, p, &flip);
    const secp256k1_ge *p_odd = tables.p_odd;
    const secp256k1_ge *p_lam_odd = tables.p_lam_odd;
    e_split.neg_k1 ^= flip;
    e_split.neg_k2 ^= flip;

    /* G tables are pre-computed */
    const secp256k1_ge *g_odd = g_odd_table;
    const secp256k1_ge *g_lam = g_lam_table;

    /* Find highest non-zero digit across all 4 streams */
    int bits = 129 + WINDOW_G;
    while (bits > 0 && wnaf_s1[bits-1] == 0 && wnaf_s2[bits-1] == 0 &&
           wnaf_e1[bits-1] == 0 && wnaf_e2[bits-1] == 0) {
        bits--;
    }
    for (int j = 0; j < q_count; j++) {
        if (q_len[j] > bits) bits = q_len[j];
    }

    gej_set_infinity(r);

    for (int i = bits - 1; i >= 0; i--) {
        gej_double(r, r);

        int d;
        secp256k1_ge pt;

        /* Stream 1: s1 (G-side) */
        d = wnaf_s1[i];
        if (d != 0) {
            int idx = (d > 0 ? d : -d) / 2;
            pt = g_odd[idx];
            if ((d < 0) ^ s_split.neg_k1) {
                fe_negate(&pt.y, &pt.y, 1);
            }
            gej_add_ge(r, r, &pt);
        }

        /* Stream 2: s2 (lambda(G)-side) */
        d = wnaf_s2[i];
        if (d != 0) {
            int idx = (d > 0 ? d : -d) / 2;
            pt = g_lam[idx];
            if ((d < 0) ^ s_split.neg_k2) {
                fe_negate(&pt.y, &pt.y, 1);
            }
            gej_add_ge(r, r, &pt);
        }

        /* Stream 3: e1 (P-side) */
        d = wnaf_e1[i];
        if (d != 0) {
            int idx = (d > 0 ? d : -d) / 2;
            pt = p_odd[idx];
            if ((d < 0) ^ e_split.neg_k1) {
                fe_negate(&pt.y, &pt.y, 1);
            }
            gej_add_ge(r, r, &pt);
        }

        /* Stream 4: e2 (lambda(P)-side) */
        d = wnaf_e2[i];
        if (d != 0) {
            int idx = (d > 0 ? d : -d) / 2;
            pt = p_lam_odd[idx];
            if ((d < 0) ^ e_split.neg_k2) {
                fe_negate(&pt.y, &pt.y, 1);
            }
            gej_add_ge(r, r, &pt);
        }

        /* Extra points Q_j, each with its own wNAF digits and affine odd-multiples table */
        for (int j = 0; j < q_count; j++) {
            if (i >= q_len[j]) continue;
            d = q_wnaf[j * q_stride + i];
            if (d == 0) continue;
            pt = q_tables[j * Q_TABLE_ENTRIES + (d > 0 ? d : -d) / 2];
            if (d < 0) fe_negate(&pt.y, &pt.y, 1);
            gej_add_ge(r, r, &pt);
        }
    }
}
