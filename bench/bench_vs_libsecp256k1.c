/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Head-to-head benchmark: libschnorr256k1 vs Bitcoin Core's libsecp256k1.
 *
 * Build:
 *   cmake .. -DBUILD_BENCH_COMPARE=ON \
 *            -DLIBSECP256K1_LIB=/path/to/libsecp256k1.so
 *   make schnorr256k1_bench_compare
 *
 * Run:
 *   ./bench/schnorr256k1_bench_compare
 */
#include "schnorr256k1.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ==================== libsecp256k1 (Bitcoin Core) declarations ==================== */
/*
 * We declare only the symbols we need via extern rather than including their
 * headers.  The benchmark links against the compiled shared library.
 */

/* Opaque context — we never inspect its contents */
typedef struct secp256k1_context_struct secp256k1_context;

/* 64-byte opaque pubkey (internal to libsecp256k1) */
typedef struct { unsigned char data[64]; } secp256k1_pubkey;

/* 32-byte x-only pubkey */
typedef struct { unsigned char data[64]; } secp256k1_xonly_pubkey;

/* 96-byte keypair (secret + public) */
typedef struct { unsigned char data[96]; } secp256k1_keypair;

#define SECP256K1_FLAGS_TYPE_CONTEXT      ((unsigned int)(1 << 0))
#define SECP256K1_FLAGS_TYPE_COMPRESSION ((unsigned int)(1 << 1))
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN ((unsigned int)(1 << 9))
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY ((unsigned int)(1 << 8))
#define SECP256K1_FLAGS_BIT_COMPRESSION  ((unsigned int)(1 << 8))

#define SECP256K1_CONTEXT_NONE \
    (SECP256K1_FLAGS_TYPE_CONTEXT)
#define SECP256K1_CONTEXT_SIGN \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
#define SECP256K1_CONTEXT_VERIFY \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
#define SECP256K1_EC_COMPRESSED \
    (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
#define SECP256K1_EC_UNCOMPRESSED \
    (SECP256K1_FLAGS_TYPE_COMPRESSION)

extern secp256k1_context *secp256k1_context_create(unsigned int flags);
extern void secp256k1_context_destroy(secp256k1_context *ctx);

extern int secp256k1_ec_pubkey_create(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *seckey
);

extern int secp256k1_ec_pubkey_serialize(
    const secp256k1_context *ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_pubkey *pubkey,
    unsigned int flags
);

extern int secp256k1_ec_pubkey_parse(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
);

extern int secp256k1_keypair_create(
    const secp256k1_context *ctx,
    secp256k1_keypair *keypair,
    const unsigned char *seckey
);

extern int secp256k1_schnorrsig_sign32(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const unsigned char *aux_rand32
);

extern int secp256k1_schnorrsig_verify(
    const secp256k1_context *ctx,
    const unsigned char *sig64,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_xonly_pubkey *pubkey
);

extern int secp256k1_keypair_xonly_pub(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *pubkey,
    int *pk_parity,
    const secp256k1_keypair *keypair
);

extern int secp256k1_xonly_pubkey_parse(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *pubkey,
    const unsigned char *input32
);

extern int secp256k1_ec_pubkey_tweak_mul(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak32
);

/* ==================== Timing ==================== */

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1.0e6;
}

static double us_per_op(double total_ms, int iters) {
    return (total_ms * 1000.0) / iters;
}

/* ==================== Number Formatting ==================== */

static const char *fmt_double(double value, int decimals) {
    static char bufs[8][64];
    static int idx = 0;
    char *buf = bufs[idx++ & 7];
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%.*f", decimals, value);
    char *dot = strchr(tmp, '.');
    int int_len = dot ? (int)(dot - tmp) : (int)strlen(tmp);
    int neg = (tmp[0] == '-') ? 1 : 0;
    int digit_count = int_len - neg;
    int commas = (digit_count - 1) / 3;
    int dst;
    dst = neg + digit_count + commas;
    if (dot) {
        int frac_len = (int)strlen(dot);
        memcpy(buf + dst, dot, (size_t)frac_len);
        buf[dst + frac_len] = '\0';
    } else {
        buf[dst] = '\0';
    }
    if (neg) buf[0] = '-';
    int src = int_len - 1;
    dst = neg + digit_count + commas - 1;
    int digits = 0;
    while (src >= neg) {
        if (digits && digits % 3 == 0)
            buf[dst--] = ',';
        buf[dst--] = tmp[src--];
        digits++;
    }
    return buf;
}

/* ==================== Test Data ==================== */

static const uint8_t TEST_PRIVKEY[32] = {
    0xd2, 0x17, 0xc1, 0xfd, 0x12, 0x40, 0xad, 0x3e,
    0xe6, 0x8f, 0x38, 0xd4, 0xab, 0x4e, 0x6e, 0x95,
    0xf2, 0x0f, 0x3e, 0x09, 0xdd, 0x51, 0x42, 0x90,
    0x00, 0xab, 0xc2, 0xb4, 0xda, 0x5b, 0xe3, 0xa3
};

static const uint8_t TEST_AUXRAND[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* ==================== Printing Helpers ==================== */

static void print_header(void) {
    printf("================================================================"
           "=========\n");
    printf("  libschnorr256k1 vs libsecp256k1 (Bitcoin Core) Benchmark\n");
    printf("================================================================"
           "=========\n\n");
}

static void print_section(const char *title) {
    printf("\n%-36s %12s %12s %10s\n", title, "THEIRS (us)", "OURS (us)", "SPEEDUP");
    printf("---------------------------------------"
           "------------------------------------\n");
}

static void print_row(const char *name, double theirs_us, double ours_us) {
    double speedup = theirs_us / ours_us;
    printf("  %-34s %12s %12s %9sx\n",
           name, fmt_double(theirs_us, 1), fmt_double(ours_us, 1),
           fmt_double(speedup, 2));
}

static void print_row_ours_only(const char *name, double ours_us) {
    printf("  %-34s %12s %12s %10s\n",
           name, "-", fmt_double(ours_us, 1), "-");
}

static void print_batch_header(void) {
    printf("\n%-36s %12s %12s %10s\n",
           "BATCH VERIFY (same pubkey)", "THEIRS/sig", "OURS/sig", "SPEEDUP");
    printf("---------------------------------------"
           "------------------------------------\n");
}

static void print_batch_row(int batch_size, double theirs_per_sig, double ours_per_sig) {
    char name[64];
    snprintf(name, sizeof(name), "%d signatures", batch_size);
    double speedup = theirs_per_sig / ours_per_sig;
    printf("  %-34s %12s %12s %9sx\n",
           name, fmt_double(theirs_per_sig, 1), fmt_double(ours_per_sig, 1),
           fmt_double(speedup, 2));
}

static void print_nostr_header(void) {
    printf("\n%-36s %12s %12s %10s\n",
           "NOSTR-SPECIFIC ADVANTAGES", "THEIRS (us)", "OURS (us)", "SPEEDUP");
    printf("---------------------------------------"
           "------------------------------------\n");
}

/* ==================== Cross-verification ==================== */

static int cross_verify(secp256k1_context *ctx) {
    int ok = 1;

    /* Derive keys with ours */
    uint8_t pub65[65];
    secp256k1c_pubkey_create(pub65, TEST_PRIVKEY);
    uint8_t xonly[32];
    memcpy(xonly, pub65 + 1, 32);

    /* Derive keypair + xonly with theirs */
    secp256k1_keypair kp;
    secp256k1_keypair_create(ctx, &kp, TEST_PRIVKEY);
    secp256k1_xonly_pubkey their_xonly;
    secp256k1_keypair_xonly_pub(ctx, &their_xonly, NULL, &kp);

    /* Hash a test message */
    uint8_t msg[32];
    secp256k1_sha256_hash(msg, (const uint8_t *)"cross-verify test", 17);

    /* sign(ours) -> verify(theirs) */
    uint8_t sig_ours[64];
    secp256k1c_schnorr_sign(sig_ours, msg, 32, TEST_PRIVKEY, TEST_AUXRAND);

    secp256k1_xonly_pubkey xpk_for_verify;
    secp256k1_xonly_pubkey_parse(ctx, &xpk_for_verify, xonly);
    if (!secp256k1_schnorrsig_verify(ctx, sig_ours, msg, 32, &xpk_for_verify)) {
        printf("FAIL: sign(ours) -> verify(theirs)\n");
        ok = 0;
    }

    /* sign(theirs) -> verify(ours) */
    uint8_t sig_theirs[64];
    secp256k1_schnorrsig_sign32(ctx, sig_theirs, msg, &kp, TEST_AUXRAND);

    if (!secp256k1c_schnorr_verify(sig_theirs, msg, 32, xonly)) {
        printf("FAIL: sign(theirs) -> verify(ours)\n");
        ok = 0;
    }

    return ok;
}

/* ==================== Head-to-head benchmarks ==================== */

static double bench_theirs_pubkey_create(secp256k1_context *ctx, int iters) {
    secp256k1_pubkey pub;
    unsigned char out[65];
    size_t outlen;
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1_ec_pubkey_create(ctx, &pub, TEST_PRIVKEY);
        outlen = 65;
        secp256k1_ec_pubkey_serialize(ctx, out, &outlen, &pub,
                                      SECP256K1_EC_UNCOMPRESSED);
    }
    return now_ms() - start;
}

static double bench_ours_pubkey_create(int iters) {
    uint8_t pub65[65];
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1c_pubkey_create(pub65, TEST_PRIVKEY);
    }
    return now_ms() - start;
}

static double bench_theirs_sign_full(secp256k1_context *ctx, const uint8_t *msg32,
                                     int iters) {
    secp256k1_keypair kp;
    uint8_t sig[64];
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1_keypair_create(ctx, &kp, TEST_PRIVKEY);
        secp256k1_schnorrsig_sign32(ctx, sig, msg32, &kp, TEST_AUXRAND);
    }
    return now_ms() - start;
}

static double bench_ours_sign_full(const uint8_t *msg32, int iters) {
    uint8_t sig[64];
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1c_schnorr_sign(sig, msg32, 32, TEST_PRIVKEY, TEST_AUXRAND);
    }
    return now_ms() - start;
}

static double bench_theirs_sign_cached(secp256k1_context *ctx,
                                       const secp256k1_keypair *kp,
                                       const uint8_t *msg32, int iters) {
    uint8_t sig[64];
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1_schnorrsig_sign32(ctx, sig, msg32, kp, TEST_AUXRAND);
    }
    return now_ms() - start;
}

static double bench_ours_sign_cached(const uint8_t *xonly,
                                     const uint8_t *msg32, int iters) {
    uint8_t sig[64];
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1c_schnorr_sign_xonly(sig, msg32, 32, TEST_PRIVKEY, xonly,
                                      TEST_AUXRAND);
    }
    return now_ms() - start;
}

static double bench_theirs_verify(secp256k1_context *ctx,
                                  const uint8_t *sig64, const uint8_t *msg32,
                                  const secp256k1_xonly_pubkey *xpk, int iters) {
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, xpk);
    }
    return now_ms() - start;
}

static double bench_ours_verify(const uint8_t *sig64, const uint8_t *msg32,
                                const uint8_t *xonly, int iters) {
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1c_schnorr_verify(sig64, msg32, 32, xonly);
    }
    return now_ms() - start;
}

static double bench_ours_verify_fast(const uint8_t *sig64, const uint8_t *msg32,
                                     const uint8_t *xonly, int iters) {
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1c_schnorr_verify_fast(sig64, msg32, 32, xonly);
    }
    return now_ms() - start;
}

static double bench_theirs_ecdh(secp256k1_context *ctx, const uint8_t *scalar32,
                                const uint8_t *pub33, int iters) {
    unsigned char out[33];
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1_pubkey pk;
        secp256k1_ec_pubkey_parse(ctx, &pk, pub33, 33);
        secp256k1_ec_pubkey_tweak_mul(ctx, &pk, scalar32);
        size_t outlen = 33;
        secp256k1_ec_pubkey_serialize(ctx, out, &outlen, &pk,
                                      SECP256K1_EC_COMPRESSED);
    }
    return now_ms() - start;
}

static double bench_ours_ecdh(const uint8_t *xonly, const uint8_t *scalar32,
                              int iters) {
    uint8_t result[32];
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1c_ecdh_xonly(result, xonly, scalar32);
    }
    return now_ms() - start;
}

/* ==================== Batch verify helpers ==================== */

typedef struct {
    uint8_t **sigs;
    uint8_t **msgs;
    size_t *lens;
    int count;
} batch_data;

static batch_data create_batch(int n) {
    batch_data b;
    b.count = n;
    b.sigs = (uint8_t **)malloc((size_t)n * sizeof(uint8_t *));
    b.msgs = (uint8_t **)malloc((size_t)n * sizeof(uint8_t *));
    b.lens = (size_t *)malloc((size_t)n * sizeof(size_t));
    for (int i = 0; i < n; i++) {
        b.msgs[i] = (uint8_t *)malloc(32);
        b.sigs[i] = (uint8_t *)malloc(64);
        b.lens[i] = 32;
        uint8_t seed[4] = {
            (uint8_t)i, (uint8_t)(i >> 8),
            (uint8_t)(i >> 16), (uint8_t)(i >> 24)
        };
        secp256k1_sha256_hash(b.msgs[i], seed, 4);
        secp256k1c_schnorr_sign(b.sigs[i], b.msgs[i], 32, TEST_PRIVKEY,
                                TEST_AUXRAND);
    }
    return b;
}

static void free_batch(batch_data *b) {
    for (int i = 0; i < b->count; i++) {
        free(b->msgs[i]);
        free(b->sigs[i]);
    }
    free(b->sigs);
    free(b->msgs);
    free(b->lens);
}

static double bench_theirs_verify_n(secp256k1_context *ctx, batch_data *b,
                                    const secp256k1_xonly_pubkey *xpk,
                                    int iters) {
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        for (int j = 0; j < b->count; j++) {
            secp256k1_schnorrsig_verify(ctx, b->sigs[j], b->msgs[j], 32, xpk);
        }
    }
    return now_ms() - start;
}

static double bench_ours_verify_batch(const uint8_t *xonly, batch_data *b,
                                      int iters) {
    double start = now_ms();
    for (int i = 0; i < iters; i++) {
        secp256k1c_schnorr_verify_batch(
            xonly,
            (const uint8_t *const *)b->sigs,
            (const uint8_t *const *)b->msgs,
            b->lens, (size_t)b->count);
    }
    return now_ms() - start;
}

/* ==================== Main ==================== */

int main(void) {
    print_header();

    /* Initialize both libraries */
    printf("Initializing libschnorr256k1...\n");
    double t0 = now_ms();
    secp256k1c_init();
    printf("  Precomputed tables: %s ms\n", fmt_double(now_ms() - t0, 1));

    printf("Initializing libsecp256k1...\n");
    t0 = now_ms();
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    printf("  Context create: %s ms\n", fmt_double(now_ms() - t0, 1));

    /* Derive shared test data */
    uint8_t pub65[65];
    secp256k1c_pubkey_create(pub65, TEST_PRIVKEY);
    uint8_t xonly[32];
    memcpy(xonly, pub65 + 1, 32);

    uint8_t pub33[33];
    secp256k1c_pubkey_compress(pub33, pub65);

    secp256k1_keypair kp;
    secp256k1_keypair_create(ctx, &kp, TEST_PRIVKEY);
    secp256k1_xonly_pubkey their_xonly;
    secp256k1_keypair_xonly_pub(ctx, &their_xonly, NULL, &kp);

    uint8_t msg[32];
    secp256k1_sha256_hash(msg, (const uint8_t *)"benchmark message", 17);

    uint8_t sig[64];
    secp256k1c_schnorr_sign(sig, msg, 32, TEST_PRIVKEY, TEST_AUXRAND);

    uint8_t scalar[32];
    secp256k1_sha256_hash(scalar, TEST_PRIVKEY, 32);
    scalar[0] &= 0x7F;

    /* Cross-verification */
    printf("\nCross-verification: ");
    if (cross_verify(ctx)) {
        printf("sign(ours)->verify(theirs)=OK, sign(theirs)->verify(ours)=OK\n");
    } else {
        printf("FAILED — aborting benchmark\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* Warmup both libraries */
    printf("\nWarming up...\n");
    bench_theirs_pubkey_create(ctx, 200);
    bench_ours_pubkey_create(200);
    bench_theirs_sign_full(ctx, msg, 200);
    bench_ours_sign_full(msg, 200);
    bench_theirs_verify(ctx, sig, msg, &their_xonly, 200);
    bench_ours_verify(sig, msg, xonly, 200);

    printf("Running benchmarks...\n");

    int N = 5000;

    /* ==================== Head-to-head ==================== */

    double theirs_ms, ours_ms;

    print_section("OPERATION");

    /* pubkeyCreate */
    theirs_ms = bench_theirs_pubkey_create(ctx, N);
    ours_ms = bench_ours_pubkey_create(N);
    print_row("pubkeyCreate", us_per_op(theirs_ms, N), us_per_op(ours_ms, N));

    /* signSchnorr (full — includes key derivation) */
    theirs_ms = bench_theirs_sign_full(ctx, msg, N);
    ours_ms = bench_ours_sign_full(msg, N);
    print_row("signSchnorr (full)", us_per_op(theirs_ms, N),
              us_per_op(ours_ms, N));

    /* signSchnorr (cached key) */
    theirs_ms = bench_theirs_sign_cached(ctx, &kp, msg, N);
    ours_ms = bench_ours_sign_cached(xonly, msg, N);
    print_row("signSchnorr (cached pubkey)", us_per_op(theirs_ms, N),
              us_per_op(ours_ms, N));

    /* verifySchnorr (full BIP-340) */
    theirs_ms = bench_theirs_verify(ctx, sig, msg, &their_xonly, N);
    ours_ms = bench_ours_verify(sig, msg, xonly, N);
    double theirs_verify_us = us_per_op(theirs_ms, N);
    double ours_verify_us = us_per_op(ours_ms, N);
    print_row("verifySchnorr (BIP-340)", theirs_verify_us, ours_verify_us);

    /* verifySchnorrFast (ours only) */
    ours_ms = bench_ours_verify_fast(sig, msg, xonly, N);
    double ours_fast_us = us_per_op(ours_ms, N);
    print_row_ours_only("verifySchnorrFast (Nostr)", ours_fast_us);

    /* ECDH */
    theirs_ms = bench_theirs_ecdh(ctx, scalar, pub33, N);
    ours_ms = bench_ours_ecdh(xonly, scalar, N);
    print_row("ECDH (x-only)", us_per_op(theirs_ms, N), us_per_op(ours_ms, N));

    /* ==================== Batch verify ==================== */

    print_batch_header();

    int batch_sizes[] = {4, 8, 16, 32, 64, 200};
    int num_batches = (int)(sizeof(batch_sizes) / sizeof(batch_sizes[0]));

    for (int b = 0; b < num_batches; b++) {
        int bs = batch_sizes[b];
        int iters = N / bs;
        if (iters < 10) iters = 10;

        batch_data bd = create_batch(bs);

        theirs_ms = bench_theirs_verify_n(ctx, &bd, &their_xonly, iters);
        ours_ms = bench_ours_verify_batch(xonly, &bd, iters);

        double theirs_per_sig = us_per_op(theirs_ms, iters) / bs;
        double ours_per_sig = us_per_op(ours_ms, iters) / bs;
        print_batch_row(bs, theirs_per_sig, ours_per_sig);

        free_batch(&bd);
    }

    /* ==================== Nostr-specific advantages ==================== */

    print_nostr_header();

    /* Fast verify vs full BIP-340 (compare against theirs full) */
    print_row("Fast verify (skip y-parity)", theirs_verify_us, ours_fast_us);

    /* Cached pubkey sign */
    theirs_ms = bench_theirs_sign_full(ctx, msg, N);
    ours_ms = bench_ours_sign_cached(xonly, msg, N);
    print_row("Cached pubkey sign", us_per_op(theirs_ms, N),
              us_per_op(ours_ms, N));

    /* Warm liftX — verify same pubkey repeatedly (second run is warm) */
    bench_ours_verify(sig, msg, xonly, 100);
    ours_ms = bench_ours_verify(sig, msg, xonly, N);
    print_row("Warm liftX (repeated pubkey)", theirs_verify_us,
              us_per_op(ours_ms, N));

    printf("\n================================================================"
           "=========\n");

    secp256k1_context_destroy(ctx);
    return 0;
}
