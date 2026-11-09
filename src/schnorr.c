/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * BIP-340 Schnorr signatures for Nostr with fast verification,
 * batch verification, and cached pubkey signing.
 */
#include "secp256k1_internal.h"
#include "field.h"
#include "scalar.h"
#include "point.h"
#include "sha256.h"
#include <string.h>
#include <stdlib.h>

/* ==================== Precomputed BIP-340 Tag Prefixes ==================== */

static uint8_t CHALLENGE_PREFIX[64];
static uint8_t AUX_PREFIX[64];
static uint8_t NONCE_PREFIX[64];
static uint8_t BATCH_PREFIX[64];

/* Called once, by secp256k1c_init. */
static void init_prefixes(void) {
    uint8_t tag_hash[32];

    secp256k1_sha256_hash(tag_hash, (const uint8_t *)"BIP0340/challenge", 17);
    memcpy(CHALLENGE_PREFIX, tag_hash, 32);
    memcpy(CHALLENGE_PREFIX + 32, tag_hash, 32);

    secp256k1_sha256_hash(tag_hash, (const uint8_t *)"BIP0340/aux", 11);
    memcpy(AUX_PREFIX, tag_hash, 32);
    memcpy(AUX_PREFIX + 32, tag_hash, 32);

    secp256k1_sha256_hash(tag_hash, (const uint8_t *)"BIP0340/nonce", 13);
    memcpy(NONCE_PREFIX, tag_hash, 32);
    memcpy(NONCE_PREFIX + 32, tag_hash, 32);

    secp256k1_sha256_hash(tag_hash, (const uint8_t *)"BIP0340/batch", 13);
    memcpy(BATCH_PREFIX, tag_hash, 32);
    memcpy(BATCH_PREFIX + 32, tag_hash, 32);
}

/* ==================== Pubkey Decompression Cache ==================== */

/* x-only key -> its even-y point. Shared by threads: each slot's lock is held only to copy an
 * entry in or out (see slot_lock), so a reader never pairs one key's bytes with another's
 * point. */
#define PUBKEY_CACHE_SIZE 1024
#define PUBKEY_CACHE_MASK (PUBKEY_CACHE_SIZE - 1)

typedef struct {
    uint8_t key_bytes[32];
    secp256k1_fe px;
    secp256k1_fe py;
    int valid;
    slot_lock lock;
} cached_pubkey;

static cached_pubkey pubkey_cache[PUBKEY_CACHE_SIZE];

static int cache_slot(const uint8_t *pub32) {
    return ((int)pub32[0] | ((int)pub32[1] << 8)) & PUBKEY_CACHE_MASK;
}

static int lift_x_cached(secp256k1_fe *out_x, secp256k1_fe *out_y, const uint8_t *pub32) {
    cached_pubkey *c = &pubkey_cache[cache_slot(pub32)];

    if (slot_lock_acquire(&c->lock)) {
        int hit = c->valid && memcmp(c->key_bytes, pub32, 32) == 0;
        if (hit) {
            *out_x = c->px;
            *out_y = c->py;
        }
        slot_lock_release(&c->lock);
        if (hit) return 1;
    }

    secp256k1_fe x;
    fe_from_bytes(&x, pub32);
    if (fe_cmp(&x, &FE_P) >= 0) return 0;
    if (!point_lift_x(out_x, out_y, &x)) return 0;

    if (slot_lock_acquire(&c->lock)) {
        memcpy(c->key_bytes, pub32, 32);
        c->px = *out_x;
        c->py = *out_y;
        c->valid = 1;
        slot_lock_release(&c->lock);
    }
    return 1;
}

/* ==================== Library Init ==================== */

/* 0: not started, 1: a thread is building the tables, 2: done. */
static unsigned char init_state;

/* Once per process, from any number of threads: the first caller builds the tables and the
 * tag prefixes, any caller meanwhile waits for it (a few milliseconds, once), and every later
 * call is one atomic load. It used to rebuild on concurrent first calls and zero the key cache
 * on every call, under the feet of threads verifying with it. */
void secp256k1c_init(void) {
    if (__atomic_load_n(&init_state, __ATOMIC_ACQUIRE) == 2) return;
    unsigned char expected = 0;
    if (__atomic_compare_exchange_n(&init_state, &expected, 1, 0, __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE)) {
        ecmult_tables_init();
        init_prefixes();
        __atomic_store_n(&init_state, 2, __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(&init_state, __ATOMIC_ACQUIRE) != 2) slot_lock_pause();
}

/* ==================== Key Operations ==================== */

int secp256k1c_pubkey_create(uint8_t *pub65, const uint8_t *seckey32) {
    secp256k1_scalar sk;
    scalar_from_bytes(&sk, seckey32);
    if (!scalar_is_valid(&sk)) return 0;

    secp256k1_gej rj;
    ecmult_gen(&rj, &sk);

    secp256k1_ge r;
    if (!gej_to_ge(&r, &rj)) return 0;

    point_serialize_uncompressed(pub65, &r);
    return 1;
}

int secp256k1c_pubkey_compress(uint8_t *pub33, const uint8_t *pub65) {
    secp256k1_ge p;
    if (!point_parse_pubkey(&p, pub65, 65)) return 0; /* 04, coordinates < p, on the curve */
    pub33[0] = (pub65[64] & 1) ? 0x03 : 0x02;
    memcpy(pub33 + 1, pub65 + 1, 32);
    return 1;
}

int secp256k1c_seckey_verify(const uint8_t *seckey32) {
    secp256k1_scalar sk;
    scalar_from_bytes(&sk, seckey32);
    return scalar_is_valid(&sk);
}

/* ==================== Schnorr Sign (internal) ==================== */

static int schnorr_sign_internal(
    uint8_t *sig64,
    const uint8_t *msg, size_t msg_len,
    const secp256k1_scalar *d0,
    const uint8_t *pub_x_bytes32,
    int pub_has_even_y,
    const uint8_t *auxrand32
) {
    secp256k1_scalar d;
    uint8_t d_bytes[32];
    secp256k1_sha256 ctx;

    /* Negate d if y is odd */
    if (pub_has_even_y) {
        d = *d0;
    } else {
        scalar_negate(&d, d0);
    }
    scalar_to_bytes(d_bytes, &d);

    /* Compute t = d XOR H(aux) */
    uint8_t t_bytes[32];
    if (auxrand32) {
        uint8_t aux_hash[32];
        secp256k1_tagged_hash_precomputed(aux_hash, AUX_PREFIX, auxrand32, 32);
        for (int i = 0; i < 32; i++) {
            t_bytes[i] = d_bytes[i] ^ aux_hash[i];
        }
    } else {
        memcpy(t_bytes, d_bytes, 32);
    }

    /* Nonce: k0 = H(t || pub || msg) */
    uint8_t rand_hash[32];
    secp256k1_sha256_init(&ctx);
    secp256k1_sha256_update(&ctx, NONCE_PREFIX, 64);
    secp256k1_sha256_update(&ctx, t_bytes, 32);
    secp256k1_sha256_update(&ctx, pub_x_bytes32, 32);
    secp256k1_sha256_update(&ctx, msg, msg_len);
    secp256k1_sha256_finalize(&ctx, rand_hash);

    secp256k1_scalar k0;
    scalar_from_bytes(&k0, rand_hash);
    scalar_reduce(&k0);
    if (scalar_is_zero(&k0)) return 0;

    /* R = k0 * G */
    secp256k1_gej rj;
    ecmult_gen(&rj, &k0);
    secp256k1_ge r;
    if (!gej_to_ge(&r, &rj)) return 0;

    /* Negate k if R.y is odd */
    secp256k1_scalar k;
    if (point_has_even_y(&r.y)) {
        k = k0;
    } else {
        scalar_negate(&k, &k0);
    }

    /* Challenge: e = H(R.x || pub || msg) */
    uint8_t rx_bytes[32], e_hash[32];
    fe_to_bytes(rx_bytes, &r.x);

    secp256k1_sha256_init(&ctx);
    secp256k1_sha256_update(&ctx, CHALLENGE_PREFIX, 64);
    secp256k1_sha256_update(&ctx, rx_bytes, 32);
    secp256k1_sha256_update(&ctx, pub_x_bytes32, 32);
    secp256k1_sha256_update(&ctx, msg, msg_len);
    secp256k1_sha256_finalize(&ctx, e_hash);

    secp256k1_scalar e;
    scalar_from_bytes(&e, e_hash);
    scalar_reduce(&e);

    /* s = k + e*d mod n */
    secp256k1_scalar ed, s;
    scalar_mul(&ed, &e, &d);
    scalar_add(&s, &k, &ed);

    /* Output signature: R.x || s */
    memcpy(sig64, rx_bytes, 32);
    scalar_to_bytes(sig64 + 32, &s);
    return 1;
}

/* ==================== Public Schnorr Sign ==================== */

int secp256k1c_schnorr_sign(
    uint8_t *sig64,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *seckey32,
    const uint8_t *auxrand32
) {
    secp256k1_scalar d0;
    scalar_from_bytes(&d0, seckey32);
    if (!scalar_is_valid(&d0)) return 0;

    /* Derive pubkey */
    secp256k1_gej pj;
    ecmult_gen(&pj, &d0);
    secp256k1_ge p;
    if (!gej_to_ge(&p, &pj)) return 0;

    uint8_t pub_x[32];
    fe_to_bytes(pub_x, &p.x);
    int even_y = point_has_even_y(&p.y);

    return schnorr_sign_internal(sig64, msg, msg_len, &d0, pub_x, even_y, auxrand32);
}

/*
 * Fast signing with pre-computed x-only pubkey.
 * ASSUMES the private key already produces an even-y pubkey (BIP-340 convention).
 * This is the case for Nostr keys managed by KeyPair, which pre-negates if needed.
 * For arbitrary keys, use secp256k1c_schnorr_sign which derives y-parity.
 */
int secp256k1c_schnorr_sign_xonly(
    uint8_t *sig64,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *seckey32,
    const uint8_t *xonly_pub32,
    const uint8_t *auxrand32
) {
    secp256k1_scalar d0;
    scalar_from_bytes(&d0, seckey32);
    if (!scalar_is_valid(&d0)) return 0;

    /* BIP-340 x-only pubkeys always have even y by convention.
     * The caller must ensure the private key produces an even-y pubkey. */
    return schnorr_sign_internal(sig64, msg, msg_len, &d0, xonly_pub32, 1, auxrand32);
}

/* ==================== Schnorr Verify (core) ==================== */

/*
 * Core verification: compute Q = s*G + (-e)*P and check X matches.
 * Returns 1 if x-coordinate matches (in Jacobian: X == r*Z^2).
 * Leaves the Jacobian result for callers that need y-parity.
 */
static int schnorr_verify_core(
    const uint8_t *sig64,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pub32,
    secp256k1_gej *result_out
) {
    /* Decompress pubkey */
    secp256k1_fe px, py;
    if (!lift_x_cached(&px, &py, pub32)) return 0;

    /* Parse r, s from signature */
    secp256k1_fe r_fe;
    fe_from_bytes(&r_fe, sig64);
    /* Check r < p */
    if (fe_cmp(&r_fe, &FE_P) >= 0) return 0;

    secp256k1_scalar s;
    scalar_from_bytes(&s, sig64 + 32);
    if (scalar_cmp(&s, &SCALAR_N) >= 0) return 0;

    /* Challenge: e = H(R.x || pub || msg) */
    uint8_t e_hash[32];
    secp256k1_sha256 ctx;
    secp256k1_sha256_init(&ctx);
    secp256k1_sha256_update(&ctx, CHALLENGE_PREFIX, 64);
    secp256k1_sha256_update(&ctx, sig64, 32); /* R.x from signature */
    secp256k1_sha256_update(&ctx, pub32, 32);
    secp256k1_sha256_update(&ctx, msg, msg_len);
    secp256k1_sha256_finalize(&ctx, e_hash);

    secp256k1_scalar e;
    scalar_from_bytes(&e, e_hash);
    scalar_reduce(&e);

    /* Q = s*G + (-e)*P via Shamir's trick */
    scalar_negate(&e, &e);
    secp256k1_ge p_aff;
    p_aff.x = px;
    p_aff.y = py;
    ecmult_double_g(result_out, &s, &p_aff, &e);

    if (gej_is_infinity(result_out)) return 0;

    /* Jacobian x-check: X == r*Z^2 (no inversion needed) */
    secp256k1_fe z2, rz2;
    fe_sqr(&z2, &result_out->z);
    fe_mul(&rz2, &r_fe, &z2);
    fe_normalize_full(&rz2);

    secp256k1_fe qx = result_out->x;
    fe_normalize_full(&qx);

    return fe_equal(&qx, &rz2);
}

/* ==================== Public Verify ==================== */

int secp256k1c_schnorr_verify(
    const uint8_t *sig64,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pub32
) {
    if (!sig64 || !pub32) return 0;

    secp256k1_gej result;
    if (!schnorr_verify_core(sig64, msg, msg_len, pub32, &result)) return 0;

    /* Full BIP-340: check y-parity (requires inversion; R is public, so variable time) */
    secp256k1_ge r_aff;
    if (!gej_to_ge_var(&r_aff, &result)) return 0;
    return point_has_even_y(&r_aff.y);
}

int secp256k1c_schnorr_verify_fast(
    const uint8_t *sig64,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pub32
) {
    if (!sig64 || !pub32) return 0;

    secp256k1_gej result;
    return schnorr_verify_core(sig64, msg, msg_len, pub32, &result);
}

/* ==================== Batch Verification ==================== */

/*
 * BIP-340 batch verification: for signatures (R_i, s_i) by one key P,
 *
 *     (sum a_i*s_i)*G == sum a_i*R_i + (sum a_i*e_i)*P
 *
 * with a_1 = 1 and the other a_i 128-bit weights from SHA-256 in counter mode, seeded by a tagged
 * hash ("BIP0340/batch") of every input: the key, each message with its 4-byte big-endian
 * length, and each signature. The same weights as libschnorr256k1-kotlin's verifySchnorrBatch.
 * Without weights the check is a plain sum and errors cancel: (R_1, s_1 + d) and (R_2, s_2 - d)
 * are both invalid and passed (libschnorr256k1-bench's KI-1). With them, making errors cancel
 * means guessing a 128-bit weight before it is known.
 *
 * It is computed as Q = s*G - e*P - sum_{i>=2} a_i*R_i, which must be lift_x(r_1): Q has
 * x = r_1 and an even y, as a single verification checks its R, so R_1 needs no square root.
 * The R_i come in chunks of BATCH_CHUNK, each with a wNAF table of odd multiples (one
 * inversion per chunk). The first chunk runs inside the G and P Strauss loop
 * (ecmult_double_g_multi), sharing its doublings; any further chunk has a Strauss loop of its own.
 */
#define BATCH_CHUNK 64
#define BATCH_WNAF_MAX 136 /* a 128-bit weight has at most 129 wNAF digits */

/* a_i for i >= 1: 16 bytes of SHA-256(seed || be32(i / 2)), the first or second half. */
static void batch_weight(secp256k1_scalar *a, const uint8_t seed[32], size_t i,
                         uint8_t block[32], size_t *block_index) {
    size_t bi = i >> 1;
    if (*block_index != bi) {
        uint8_t counter[36];
        memcpy(counter, seed, 32);
        counter[32] = (uint8_t)(bi >> 24); counter[33] = (uint8_t)(bi >> 16);
        counter[34] = (uint8_t)(bi >> 8);  counter[35] = (uint8_t)bi;
        secp256k1_sha256_hash(block, counter, 36);
        *block_index = bi;
    }
    uint8_t bytes[32] = {0};
    memcpy(bytes + 16, block + (i & 1) * 16, 16);
    scalar_from_bytes(a, bytes);
    if (scalar_is_zero(a)) a->d[0] = 1;
}

/* r (< p), s (< n) and e = H(r || pub || msg) of one signature. */
static int batch_parse(secp256k1_fe *r, secp256k1_scalar *s, secp256k1_scalar *e,
                       const uint8_t *sig, const uint8_t *pub32,
                       const uint8_t *msg, size_t msg_len) {
    fe_from_bytes(r, sig);
    if (fe_cmp(r, &FE_P) >= 0) return 0;
    scalar_from_bytes(s, sig + 32);
    if (scalar_cmp(s, &SCALAR_N) >= 0) return 0;

    uint8_t e_hash[32];
    secp256k1_sha256 ctx;
    secp256k1_sha256_init(&ctx);
    secp256k1_sha256_update(&ctx, CHALLENGE_PREFIX, 64);
    secp256k1_sha256_update(&ctx, sig, 32);
    secp256k1_sha256_update(&ctx, pub32, 32);
    secp256k1_sha256_update(&ctx, msg, msg_len);
    secp256k1_sha256_finalize(&ctx, e_hash);
    scalar_from_bytes(e, e_hash);
    scalar_reduce(e);
    return 1;
}

typedef struct {
    secp256k1_ge table[BATCH_CHUNK * Q_TABLE_ENTRIES];
    secp256k1_gej scratch[BATCH_CHUNK * Q_TABLE_ENTRIES];
    secp256k1_ge r[BATCH_CHUNK];
    int8_t wnaf[BATCH_CHUNK][BATCH_WNAF_MAX];
    int wnaf_len[BATCH_CHUNK];
    int count;
    int max_len;
} batch_chunk;

/* Signatures [from, to) (from >= 1): adds a_i*s_i and a_i*e_i to the sums, and fills the chunk
 * with each R_i's table and the wNAF digits of -a_i. */
static int batch_prepare(batch_chunk *c, size_t from, size_t to, const uint8_t *pub32,
                         const uint8_t *const *sigs64, const uint8_t *const *msgs,
                         const size_t *msg_lens, const uint8_t seed[32], uint8_t block[32],
                         size_t *block_index, secp256k1_scalar *s_sum, secp256k1_scalar *e_sum) {
    int digits[BATCH_WNAF_MAX];
    c->count = (int)(to - from);
    c->max_len = 0;
    for (size_t i = from; i < to; i++) {
        size_t j = i - from;
        secp256k1_fe r_fe;
        secp256k1_scalar s, e, a, t;
        if (!batch_parse(&r_fe, &s, &e, sigs64[i], pub32, msgs[i], msg_lens[i])) return 0;
        if (!point_lift_x(&c->r[j].x, &c->r[j].y, &r_fe)) return 0;

        batch_weight(&a, seed, i, block, block_index);
        scalar_mul(&t, &a, &s);
        scalar_add(s_sum, s_sum, &t);
        scalar_mul(&t, &a, &e);
        scalar_add(e_sum, e_sum, &t);

        int len = wnaf_encode(digits, BATCH_WNAF_MAX, &a, Q_WINDOW);
        for (int k = 0; k < len; k++) c->wnaf[j][k] = (int8_t)-digits[k];
        c->wnaf_len[j] = len;
        if (len > c->max_len) c->max_len = len;
    }
    ecmult_odd_multiples_affine(c->table, c->r, c->count, c->scratch);
    return 1;
}

/* The rest of the batch once signature 1 is parsed, with the chunk buffers on the heap. */
static int batch_finish(batch_chunk *chunk, const uint8_t *pub32, const uint8_t *const *sigs64,
                        const uint8_t *const *msgs, const size_t *msg_lens, size_t count,
                        const uint8_t seed[32], uint8_t block[32], size_t *block_index,
                        const secp256k1_fe *r1, secp256k1_scalar s_sum, secp256k1_scalar e_sum,
                        const secp256k1_fe *px, const secp256k1_fe *py) {

    /* Chunks after the first: extra = -sum a_i*R_i over them, each with its own Strauss loop */
    secp256k1_gej extra;
    gej_set_infinity(&extra);
    for (size_t from = 1 + BATCH_CHUNK; from < count; from += BATCH_CHUNK) {
        size_t to = from + BATCH_CHUNK < count ? from + BATCH_CHUNK : count;
        if (!batch_prepare(chunk, from, to, pub32, sigs64, msgs, msg_lens, seed, block,
                           block_index, &s_sum, &e_sum)) return 0;
        secp256k1_gej acc;
        gej_set_infinity(&acc);
        for (int bit = chunk->max_len - 1; bit >= 0; bit--) {
            gej_double(&acc, &acc);
            for (int j = 0; j < chunk->count; j++) {
                if (bit >= chunk->wnaf_len[j]) continue;
                int d = chunk->wnaf[j][bit];
                if (d == 0) continue;
                secp256k1_ge pt = chunk->table[j * Q_TABLE_ENTRIES + (d > 0 ? d : -d) / 2];
                if (d < 0) fe_negate(&pt.y, &pt.y, 1);
                gej_add_ge(&acc, &acc, &pt);
            }
        }
        gej_add(&extra, &extra, &acc);
    }

    /* The first chunk, inside the G and P loop: Q = s*G - e*P - sum a_i*R_i */
    size_t first_to = 1 + BATCH_CHUNK < count ? 1 + BATCH_CHUNK : count;
    if (!batch_prepare(chunk, 1, first_to, pub32, sigs64, msgs, msg_lens, seed, block,
                       block_index, &s_sum, &e_sum)) return 0;
    scalar_negate(&e_sum, &e_sum);
    secp256k1_ge p_aff = {.x = *px, .y = *py};
    secp256k1_gej q;
    ecmult_double_g_multi(&q, &s_sum, &p_aff, &e_sum, chunk->table, &chunk->wnaf[0][0],
                          BATCH_WNAF_MAX, chunk->wnaf_len, chunk->count);
    gej_add(&q, &q, &extra);

    /* Q must be lift_x(r_1): x = r_1 and y even */
    secp256k1_ge q_aff;
    if (!gej_to_ge_var(&q_aff, &q)) return 0;
    if (!fe_equal(&q_aff.x, r1)) return 0;
    return point_has_even_y(&q_aff.y);
}

int secp256k1c_schnorr_verify_batch(
    const uint8_t *pub32,
    const uint8_t *const *sigs64,
    const uint8_t *const *msgs,
    const size_t *msg_lens,
    size_t count
) {
    if (count == 0) return 1;
    if (count == 1) return secp256k1c_schnorr_verify(sigs64[0], msgs[0], msg_lens[0], pub32);
    if (!pub32) return 0;

    secp256k1_fe px, py;
    if (!lift_x_cached(&px, &py, pub32)) return 0;

    /* seed = tagged hash of pub || (len(msg_i) || msg_i)... || sig_i... */
    uint8_t seed[32];
    {
        secp256k1_sha256 ctx;
        secp256k1_sha256_init(&ctx);
        secp256k1_sha256_update(&ctx, BATCH_PREFIX, 64);
        secp256k1_sha256_update(&ctx, pub32, 32);
        for (size_t i = 0; i < count; i++) {
            if (!sigs64[i]) return 0;
            uint8_t len[4] = {(uint8_t)(msg_lens[i] >> 24), (uint8_t)(msg_lens[i] >> 16),
                              (uint8_t)(msg_lens[i] >> 8), (uint8_t)msg_lens[i]};
            secp256k1_sha256_update(&ctx, len, 4);
            secp256k1_sha256_update(&ctx, msgs[i], msg_lens[i]);
        }
        for (size_t i = 0; i < count; i++) secp256k1_sha256_update(&ctx, sigs64[i], 64);
        secp256k1_sha256_finalize(&ctx, seed);
    }
    uint8_t block[32];
    size_t block_index = (size_t)-1;

    /* Signature 1, weight 1 */
    secp256k1_fe r1;
    secp256k1_scalar s_sum, e_sum;
    if (!batch_parse(&r1, &s_sum, &e_sum, sigs64[0], pub32, msgs[0], msg_lens[0])) return 0;

    /* The chunk's tables and digits (~56 KB) live on the heap: on the stack they overflowed small
     * thread stacks (a batch of 8 crashed at 64 KB). Without memory, verify one by one. */
    batch_chunk *chunk = (batch_chunk *)malloc(sizeof(batch_chunk));
    if (!chunk) {
        for (size_t i = 0; i < count; i++) {
            if (!secp256k1c_schnorr_verify(sigs64[i], msgs[i], msg_lens[i], pub32)) return 0;
        }
        return 1;
    }
    int ok = batch_finish(chunk, pub32, sigs64, msgs, msg_lens, count, seed, block, &block_index,
                          &r1, s_sum, e_sum, &px, &py);
    free(chunk);
    return ok;
}

/* ==================== Tweak Operations ==================== */

int secp256k1c_privkey_tweak_add(uint8_t *result32, const uint8_t *seckey32, const uint8_t *tweak32) {
    secp256k1_scalar a, b, r;
    scalar_from_bytes(&a, seckey32);
    scalar_from_bytes(&b, tweak32);
    scalar_add(&r, &a, &b);
    if (scalar_is_zero(&r) || scalar_cmp(&r, &SCALAR_N) >= 0) return 0;
    scalar_to_bytes(result32, &r);
    return 1;
}

int secp256k1c_pubkey_tweak_mul(uint8_t *result, size_t result_len,
                                 const uint8_t *pubkey, size_t pubkey_len,
                                 const uint8_t *tweak32) {
    secp256k1_ge p;
    if (!point_parse_pubkey(&p, pubkey, pubkey_len)) return 0;

    secp256k1_scalar scalar;
    scalar_from_bytes(&scalar, tweak32);
    if (!scalar_is_valid(&scalar)) return 0;

    secp256k1_gej rj;
    ecmult(&rj, &p, &scalar);

    secp256k1_ge r;
    if (!gej_to_ge(&r, &rj)) return 0;

    if (result_len == 33) {
        point_serialize_compressed(result, &r);
    } else if (result_len == 65) {
        point_serialize_uncompressed(result, &r);
    } else {
        return 0;
    }
    return 1;
}

int secp256k1c_ecdh_xonly(uint8_t *result32, const uint8_t *xonly_pub32, const uint8_t *scalar32) {
    /* Use cached liftX — same peer key in NIP-44 conversations */
    secp256k1_fe px, py;
    if (!lift_x_cached(&px, &py, xonly_pub32)) return 0;

    secp256k1_scalar k;
    scalar_from_bytes(&k, scalar32);
    if (!scalar_is_valid(&k)) return 0;

    secp256k1_gej rj;
    const secp256k1_ge p = {.x = px, .y = py};
    ecmult(&rj, &p, &k);

    secp256k1_fe rx;
    if (!gej_to_ge_x(&rx, &rj)) return 0;
    fe_to_bytes(result32, &rx);
    return 1;
}

/* ==================== SHA-256 Public Wrappers ==================== */

void secp256k1c_sha256(uint8_t *out32, const uint8_t *data, size_t len) {
    secp256k1_sha256_hash(out32, data, len);
}

void secp256k1c_tagged_hash(uint8_t *out32, const char *tag,
                             const uint8_t *msg, size_t msg_len) {
    secp256k1_tagged_hash(out32, tag, msg, msg_len);
}
