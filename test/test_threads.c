/*
 * The shared caches under concurrent use. Each slot of the point-table cache and of the x-only
 * key cache is written by whichever thread misses on it, so two keys that land in the same slot
 * rewrite it in turn. Without a lock, a reader could pair one key with the other's tables or
 * coordinates: valid signatures were rejected, and a signature made with Q's secret over P's x
 * verified as P's while another thread verified Q's.
 */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "test_framework.h"
#include "schnorr256k1.h"
#include "scalar.h"

#define ROUNDS 5000

/* The slot functions of point.c (p_cache_slot) and schnorr.c (cache_slot), on big-endian x */
static int table_slot(const uint8_t *x) {
    uint64_t d0 = 0, d1 = 0;
    for (int i = 0; i < 8; i++) { d0 = d0 << 8 | x[24 + i]; d1 = d1 << 8 | x[16 + i]; }
    return (int)(d0 ^ (d1 << 3)) & 1023;
}
static int key_slot(const uint8_t *x) { return (x[0] | x[1] << 8) & 1023; }

typedef struct {
    const uint8_t *pub, *sig, *forged;
    uint8_t msg[32];
    long wrong;
} job;

static void *verify_loop(void *arg) {
    job *j = (job *)arg;
    for (int i = 0; i < ROUNDS; i++) {
        if (!secp256k1c_schnorr_verify(j->sig, j->msg, 32, j->pub)) j->wrong++;
        if (j->forged && secp256k1c_schnorr_verify(j->forged, j->msg, 32, j->pub)) j->wrong++;
    }
    return NULL;
}

/* A key Q with even y whose x shares P's slot in one cache (same_table) or the other. */
static void colliding_key(uint8_t secq[32], uint8_t pubq[65], const uint8_t *pubp, int same_table) {
    for (uint32_t i = 1;; i++) {
        memset(secq, 0, 32);
        secq[0] = 0x2C;
        secq[28] = (uint8_t)(i >> 24); secq[29] = (uint8_t)(i >> 16);
        secq[30] = (uint8_t)(i >> 8);  secq[31] = (uint8_t)i;
        ASSERT_TRUE(secp256k1c_pubkey_create(pubq, secq));
        if (pubq[64] & 1) continue;
        int t = table_slot(pubq + 1) == table_slot(pubp + 1);
        int k = key_slot(pubq + 1) == key_slot(pubp + 1);
        if (same_table ? (t && !k) : (k && !t)) return;
    }
}

/* s = k + H(R || Px || m) * q: a signature by Q's secret whose challenge names P */
static void forge(uint8_t sig[64], const uint8_t *secq, const uint8_t *pubp, const uint8_t msg[32]) {
    uint8_t kb[32], r65[65], pre[96], eb[32];
    memset(kb, 0x6B, 32);
    ASSERT_TRUE(secp256k1c_pubkey_create(r65, kb));
    secp256k1_scalar k, e, q, s;
    scalar_from_bytes(&k, kb);
    if (r65[64] & 1) scalar_negate(&k, &k); /* R with even y */
    memcpy(pre, r65 + 1, 32);
    memcpy(pre + 32, pubp + 1, 32);
    memcpy(pre + 64, msg, 32);
    secp256k1c_tagged_hash(eb, "BIP0340/challenge", pre, 96);
    scalar_from_bytes(&e, eb);
    scalar_reduce(&e);
    scalar_from_bytes(&q, secq);
    scalar_mul(&s, &e, &q);
    scalar_add(&s, &s, &k);
    memcpy(sig, r65 + 1, 32);
    scalar_to_bytes(sig + 32, &s);
}

static void run_pair(int same_table) {
    uint8_t secp[32], pubp[65], secq[32], pubq[65], sigp[64], sigq[64], forged[64];
    memset(secp, 0, 32);
    secp[0] = 0x11; secp[31] = 0x07;
    ASSERT_TRUE(secp256k1c_pubkey_create(pubp, secp));
    colliding_key(secq, pubq, pubp, same_table);

    job a = { .pub = pubp + 1, .sig = sigp, .forged = forged, .wrong = 0 };
    job b = { .pub = pubq + 1, .sig = sigq, .forged = NULL, .wrong = 0 };
    memset(a.msg, 0x01, 32);
    memset(b.msg, 0x01, 32);
    ASSERT_TRUE(secp256k1c_schnorr_sign(sigp, a.msg, 32, secp, NULL));
    ASSERT_TRUE(secp256k1c_schnorr_sign(sigq, b.msg, 32, secq, NULL));
    forge(forged, secq, pubp, a.msg);
    ASSERT_FALSE(secp256k1c_schnorr_verify(forged, a.msg, 32, pubp + 1));

    pthread_t ta, tb;
    ASSERT_TRUE(pthread_create(&ta, NULL, verify_loop, &a) == 0);
    ASSERT_TRUE(pthread_create(&tb, NULL, verify_loop, &b) == 0);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    ASSERT_EQ_INT(a.wrong + b.wrong, 0);
}

static volatile int init_stop;

static void *init_loop(void *arg) {
    (void)arg;
    while (!init_stop) secp256k1c_init();
    return NULL;
}

/* secp256k1c_init is idempotent: calling it again while other threads verify changes nothing.
 * (It zeroed the key cache, locks included, on every call.) */
static void init_while_verifying(void) {
    pthread_t t;
    init_stop = 0;
    ASSERT_TRUE(pthread_create(&t, NULL, init_loop, NULL) == 0);
    run_pair(0);
    run_pair(1);
    init_stop = 1;
    pthread_join(t, NULL);
}

static void table_cache_is_thread_safe(void) { run_pair(1); }
static void key_cache_is_thread_safe(void) { run_pair(0); }

void run_thread_tests(void) {
    SUITE(threads);
    printf("Running thread-safety tests...\n");
    TEST(table_cache_is_thread_safe);
    TEST(key_cache_is_thread_safe);
    TEST(init_while_verifying);
    printf("  Threads: done\n");
}
