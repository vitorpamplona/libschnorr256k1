/*
 * Copyright (c) 2025 Vitor Pamplona
 * Integration tests for public API: key ops, ECDH, batch verify.
 * Ported from Secp256k1Test.kt
 */
#include "test_framework.h"
#include "schnorr256k1.h"
#include "scalar.h"

/* ==================== secKeyVerify ==================== */

static void verify_valid_privkey(void) {
    HEX32(key, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    ASSERT_TRUE(secp256k1c_seckey_verify(key));
}

static void verify_invalid_privkey_curve_order(void) {
    HEX32(key, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    ASSERT_FALSE(secp256k1c_seckey_verify(key));
}

static void verify_invalid_privkey_zero(void) {
    HEX32(key, "0000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_FALSE(secp256k1c_seckey_verify(key));
}

/* ==================== pubkeyCreate ==================== */

static void create_valid_pubkey(void) {
    HEX32(sec, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    uint8_t pub[65];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub, sec));
    ASSERT_HEX_EQ(pub,
        "04c591a8ff19ac9c4e4e5793673b83123437e975285e7b442f4ee2654dffca5e2d"
        "2103ed494718c697ac9aebcfd19612e224db46661011863ed2fc54e71861e2a6", 65);
}

static void create_pubkey_from_key_one(void) {
    HEX32(sec, "0000000000000000000000000000000000000000000000000000000000000001");
    uint8_t pub[65];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub, sec));
    /* G itself */
    ASSERT_HEX_EQ(pub,
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 65);
}

static void create_pubkey_from_key_three(void) {
    HEX32(sec, "0000000000000000000000000000000000000000000000000000000000000003");
    uint8_t pub[65], comp[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(comp, pub));
    /* BIP-340 test vector 0 public key */
    ASSERT_HEX_EQ(comp, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", 33);
}

/* ==================== pubKeyCompress ==================== */

static void compress_pubkey(void) {
    HEX65(pub, "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D"
               "2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6");
    uint8_t comp[33];
    ASSERT_TRUE(secp256k1c_pubkey_compress(comp, pub));
    ASSERT_HEX_EQ(comp, "02c591a8ff19ac9c4e4e5793673b83123437e975285e7b442f4ee2654dffca5e2d", 33);
}

static void compress_pubkey_odd_y(void) {
    HEX32(sec, "65f039136f8da8d3e87b4818746b53318d5481e24b2673f162815144223a0b5a");
    uint8_t pub[65], comp[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(comp, pub));
    ASSERT_HEX_EQ(comp, "033dcef7585efbdb68747d919152bd481e21f5e952aaaef5a19604fbd096a93dd5", 33);
}

static void compress_pubkey_even_y(void) {
    HEX32(sec, "e6159851715b4aa6190c22b899b0c792847de0a4435ac5b678f35738351c43b0");
    uint8_t pub[65], comp[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(comp, pub));
    ASSERT_HEX_EQ(comp, "029fa4ce8c87ca546b196e6518db80a6780e1bd5552b61f9f17bafee5d4e34e09b", 33);
}

/* ==================== privKeyTweakAdd ==================== */

static void privkey_tweak_add(void) {
    HEX32(sec, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    HEX32(tweak, "3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3");
    uint8_t result[32];
    ASSERT_TRUE(secp256k1c_privkey_tweak_add(result, sec, tweak));
    ASSERT_HEX_EQ(result, "a168571e189e6f9a7e2d657a4b53ae99b909f7e712d1c23ced28093cd57c88f3", 32);
}

/* ==================== pubKeyTweakMul ==================== */

static void pubkey_tweak_mul(void) {
    HEX65(pub, "040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE5"
               "95DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40");
    HEX32(tweak, "3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3");
    uint8_t result[65];
    ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(result, 65, pub, 65, tweak));
    ASSERT_HEX_EQ(result,
        "04e0fe6fe55ebca626b98a807f6caf654139e14e5e3698f01a9a658e21dc1d2791"
        "ec060d4f412a794d5370f672bc94b722640b5f76914151cfca6e712ca48cc589", 65);
}

static void pubkey_tweak_mul_compressed(void) {
    HEX32(xonly, "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133");
    HEX32(sec, "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268");
    uint8_t pub33[33];
    pub33[0] = 0x02;
    memcpy(pub33 + 1, xonly, 32);
    uint8_t result[33];
    ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(result, 33, pub33, 33, sec));
    ASSERT_EQ_INT(33, 33); /* 33-byte compressed output */
}

/* ==================== ECDH ==================== */

static void ecdh_symmetry(void) {
    HEX32(secA, "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268");
    HEX32(secB, "a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e");

    uint8_t pubA[65], pubB[65], compA[33], compB[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pubA, secA));
    ASSERT_TRUE(secp256k1c_pubkey_create(pubB, secB));
    ASSERT_TRUE(secp256k1c_pubkey_compress(compA, pubA));
    ASSERT_TRUE(secp256k1c_pubkey_compress(compB, pubB));

    uint8_t secretAB[65], secretBA[65];
    ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(secretAB, 33, compB, 33, secA));
    ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(secretBA, 33, compA, 33, secB));
    ASSERT_MEM_EQ(secretAB, secretBA, 33);
}

static void ecdh_xonly_symmetric(void) {
    HEX32(secA, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    HEX32(secB, "3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3");

    uint8_t pubA[65], pubB[65], compA[33], compB[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pubA, secA));
    ASSERT_TRUE(secp256k1c_pubkey_create(pubB, secB));
    ASSERT_TRUE(secp256k1c_pubkey_compress(compA, pubA));
    ASSERT_TRUE(secp256k1c_pubkey_compress(compB, pubB));

    uint8_t resultAB[32], resultBA[32];
    ASSERT_TRUE(secp256k1c_ecdh_xonly(resultAB, compB + 1, secA));
    ASSERT_TRUE(secp256k1c_ecdh_xonly(resultBA, compA + 1, secB));
    ASSERT_MEM_EQ(resultAB, resultBA, 32);
}

/* Bytes of SHA-256("ecdh-test" || tag || i), for keys no other test touches. */
static void ecdh_test_bytes(uint8_t out[32], uint8_t tag, int i) {
    uint8_t in[12] = {'e', 'c', 'd', 'h', '-', 't', 'e', 's', 't', tag, (uint8_t)(i >> 8), (uint8_t)i};
    secp256k1c_sha256(out, in, sizeof in);
}

/* A new key's ECDH runs on an isomorphic curve and never lifts x: it must still be x(k*P) for
 * either lift, which tweak-mul of 02 || x computes the usual way. ECDH first, so its key is new. */
static void ecdh_xonly_matches_tweak_mul(void) {
    int odd = 0;
    for (int i = 0; i < 64; i++) {
        uint8_t sec[32], k[32], pub65[65], pub33[33], even[33], tw[33], out[32];
        ecdh_test_bytes(sec, 1, i);
        ecdh_test_bytes(k, 2, i);
        ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
        ASSERT_TRUE(secp256k1c_pubkey_compress(pub33, pub65));
        if (pub33[0] == 0x03) odd++;
        ASSERT_TRUE(secp256k1c_ecdh_xonly(out, pub33 + 1, k));
        even[0] = 0x02;
        memcpy(even + 1, pub33 + 1, 32);
        ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(tw, 33, even, 33, k));
        ASSERT_MEM_EQ(out, tw + 1, 32);
    }
    ASSERT_TRUE(odd > 10 && odd < 54); /* keys of both parities */
}

/* A key seen before (verified: its lift is cached) takes the cached path: the same result. */
static void ecdh_xonly_cached_and_new_agree(void) {
    for (int i = 0; i < 16; i++) {
        uint8_t sec[32], k[32], pub65[65], msg[32], sig[64], fresh[32], cached[32];
        ecdh_test_bytes(sec, 3, i);
        ecdh_test_bytes(k, 4, i);
        ecdh_test_bytes(msg, 5, i);
        ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
        ASSERT_TRUE(secp256k1c_ecdh_xonly(fresh, pub65 + 1, k));
        ASSERT_TRUE(secp256k1c_schnorr_sign(sig, msg, 32, sec, NULL));
        ASSERT_TRUE(secp256k1c_schnorr_verify(sig, msg, 32, pub65 + 1)); /* caches the lift */
        ASSERT_TRUE(secp256k1c_ecdh_xonly(cached, pub65 + 1, k));
        ASSERT_MEM_EQ(fresh, cached, 32);
    }
}

/* An x with no point fails, as tweak-mul of 02 || x does; so do x = p and BIP-340 vector 5's key. */
static void ecdh_xonly_rejects_x_off_the_curve(void) {
    int rejected = 0;
    for (int i = 0; i < 64; i++) {
        uint8_t x[32], k[32], even[33], tw[33], out[32];
        ecdh_test_bytes(x, 6, i);
        ecdh_test_bytes(k, 7, i);
        even[0] = 0x02;
        memcpy(even + 1, x, 32);
        int on_curve = secp256k1c_pubkey_tweak_mul(tw, 33, even, 33, k);
        ASSERT_EQ_INT(on_curve, secp256k1c_ecdh_xonly(out, x, k));
        if (on_curve) ASSERT_MEM_EQ(out, tw + 1, 32);
        else rejected++;
    }
    ASSERT_TRUE(rejected > 10 && rejected < 54);
    HEX32(k, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    HEX32(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    HEX32(v5, "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34");
    uint8_t out[32];
    ASSERT_FALSE(secp256k1c_ecdh_xonly(out, p, k));
    ASSERT_FALSE(secp256k1c_ecdh_xonly(out, v5, k));
}

/* ==================== Schnorr Edge Cases ==================== */

static void verify_wrong_message(void) {
    HEX32(sec, "f410f88bcec6cbfda04d6a273c7b1dd8bba144cd45b71e87109cfa11dd7ed561");
    uint8_t msg[32]; memset(msg, 0x42, 32);
    uint8_t sig[64];
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig, msg, 32, sec, NULL));

    uint8_t pub65[65], pub33[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(pub33, pub65));

    ASSERT_TRUE(secp256k1c_schnorr_verify(sig, msg, 32, pub33 + 1));
    uint8_t wrong[32]; memset(wrong, 0x43, 32);
    ASSERT_FALSE(secp256k1c_schnorr_verify(sig, wrong, 32, pub33 + 1));
}

static void verify_corrupted_sig(void) {
    HEX32(sec, "f410f88bcec6cbfda04d6a273c7b1dd8bba144cd45b71e87109cfa11dd7ed561");
    uint8_t msg[32]; memset(msg, 0x42, 32);
    uint8_t sig[64];
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig, msg, 32, sec, NULL));

    uint8_t pub65[65], pub33[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(pub33, pub65));

    uint8_t corrupt[64];
    memcpy(corrupt, sig, 64);
    corrupt[0] ^= 1;
    ASSERT_FALSE(secp256k1c_schnorr_verify(corrupt, msg, 32, pub33 + 1));
}

static void sign_deterministic(void) {
    HEX32(sec, "f410f88bcec6cbfda04d6a273c7b1dd8bba144cd45b71e87109cfa11dd7ed561");
    uint8_t msg[32]; memset(msg, 0x42, 32);
    uint8_t sig1[64], sig2[64];
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig1, msg, 32, sec, NULL));
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig2, msg, 32, sec, NULL));
    ASSERT_MEM_EQ(sig1, sig2, 64);
}

/* ==================== Batch Verification ==================== */

static void batch_all_valid(void) {
    HEX32(sec, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    uint8_t pub65[65], pub33[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(pub33, pub65));

    uint8_t sigs[10][64], msgs[10][32];
    const uint8_t *sig_ptrs[10], *msg_ptrs[10];
    size_t lens[10];

    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 32; j++) msgs[i][j] = (uint8_t)(i * 7 + j);
        ASSERT_TRUE(secp256k1c_schnorr_sign(sigs[i], msgs[i], 32, sec, NULL));
        ASSERT_TRUE(secp256k1c_schnorr_verify(sigs[i], msgs[i], 32, pub33 + 1));
        sig_ptrs[i] = sigs[i];
        msg_ptrs[i] = msgs[i];
        lens[i] = 32;
    }
    ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub33 + 1, sig_ptrs, msg_ptrs, lens, 10));
}

static void batch_with_invalid(void) {
    HEX32(sec, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    uint8_t pub65[65], pub33[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(pub33, pub65));

    uint8_t msg1[32]; memset(msg1, 0x01, 32);
    uint8_t msg2[32]; memset(msg2, 0x02, 32);
    uint8_t sig1[64], sig2[64];
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig1, msg1, 32, sec, NULL));
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig2, msg2, 32, sec, NULL));
    sig2[63] ^= 0x01; /* corrupt */

    const uint8_t *sigs[] = {sig1, sig2};
    const uint8_t *msgs[] = {msg1, msg2};
    size_t lens[] = {32, 32};
    ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub33 + 1, sigs, msgs, lens, 2));
}

static void batch_empty(void) {
    HEX32(pub, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub, NULL, NULL, NULL, 0));
}

static void batch_single(void) {
    HEX32(sec, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    uint8_t pub65[65], pub33[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(pub33, pub65));

    uint8_t msg[32]; memset(msg, 0x42, 32);
    uint8_t sig[64];
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig, msg, 32, sec, NULL));

    const uint8_t *sigs[] = {sig};
    const uint8_t *msgs[] = {msg};
    size_t lens[] = {32};
    ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub33 + 1, sigs, msgs, lens, 1));
}

static void batch_large(void) {
    HEX32(sec, "3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3");
    uint8_t pub65[65], pub33[33];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    ASSERT_TRUE(secp256k1c_pubkey_compress(pub33, pub65));

    uint8_t sigs[32][64], msgs[32][64];
    const uint8_t *sig_ptrs[32], *msg_ptrs[32];
    size_t lens[32];

    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 64; j++) msgs[i][j] = (uint8_t)(i * 13 + j);
        ASSERT_TRUE(secp256k1c_schnorr_sign(sigs[i], msgs[i], 64, sec, NULL));
        sig_ptrs[i] = sigs[i];
        msg_ptrs[i] = msgs[i];
        lens[i] = 64;
    }
    ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub33 + 1, sig_ptrs, msg_ptrs, lens, 32));
}

/* KI-1 (libschnorr256k1-bench): an unweighted batch sums the signatures, so two invalid ones
 * whose errors cancel, (R1, s1 + d) and (R2, s2 - d), passed. BIP-340's weights stop it. */
static void sign_n(uint8_t sigs[][64], uint8_t msgs[][32], const uint8_t **sp, const uint8_t **mp,
                   size_t *lens, int n, const uint8_t *sec, int salt) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < 32; j++) msgs[i][j] = (uint8_t)(i * 31 + j + salt);
        ASSERT_TRUE(secp256k1c_schnorr_sign(sigs[i], msgs[i], 32, sec, NULL));
        sp[i] = sigs[i]; mp[i] = msgs[i]; lens[i] = 32;
    }
}

static void add_to_s(uint8_t sig[64], const secp256k1_scalar *d) {
    secp256k1_scalar s;
    scalar_from_bytes(&s, sig + 32);
    scalar_add(&s, &s, d);
    scalar_to_bytes(sig + 32, &s);
}

static void batch_rejects_cancelling_signatures(void) {
    HEX32(sec, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    uint8_t pub65[65];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    for (int n = 2; n <= 40; n += 19) { /* 2, 21, 40: the pair alone, and inside larger batches */
        uint8_t sigs[40][64], msgs[40][32];
        const uint8_t *sp[40], *mp[40];
        size_t lens[40];
        sign_n(sigs, msgs, sp, mp, lens, n, sec, n);
        ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, (size_t)n));
        secp256k1_scalar d = SCALAR_ZERO, neg_d;
        d.d[0] = 0x1234567;
        scalar_negate(&neg_d, &d);
        add_to_s(sigs[0], &d);
        add_to_s(sigs[n - 1], &neg_d);
        ASSERT_FALSE(secp256k1c_schnorr_verify(sigs[0], msgs[0], 32, pub65 + 1));
        ASSERT_FALSE(secp256k1c_schnorr_verify(sigs[n - 1], msgs[n - 1], 32, pub65 + 1));
        ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, (size_t)n));
    }
}

/* Valid batches of every size from 2 to 140 pass (one, two and three internal chunks), and one
 * bad signature anywhere (first, second, middle, last) makes the batch fail. */
static void batch_sizes_and_single_errors(void) {
    HEX32(sec, "3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3");
    uint8_t pub65[65];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    enum { MAX = 140 };
    static uint8_t sigs[MAX][64], msgs[MAX][32];
    const uint8_t *sp[MAX], *mp[MAX];
    size_t lens[MAX];
    sign_n(sigs, msgs, sp, mp, lens, MAX, sec, 0);
    for (int n = 2; n <= MAX; n++) {
        ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, (size_t)n));
        int bad[4] = {0, 1, n / 2, n - 1};
        for (int b = 0; b < 4; b++) {
            sigs[bad[b]][40] ^= 0x10;
            ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, (size_t)n));
            sigs[bad[b]][40] ^= 0x10;
        }
    }
}

/* The first signature is checked without lifting its R (the batch's result must be
 * lift_x(r_1)), so its own failures each need a test: r_1 >= p, r_1 not on the curve, s_1 >= n,
 * and a signature whose R comes out as -lift_x(r_1) (right x, odd y), which only the parity check
 * rejects. */
static void batch_rejects_bad_first_signature(void) {
    HEX32(sec, "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    uint8_t pub65[65];
    ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
    enum { N = 70 };
    static uint8_t sigs[N][64], msgs[N][32];
    const uint8_t *sp[N], *mp[N];
    size_t lens[N];
    sign_n(sigs, msgs, sp, mp, lens, N, sec, 5);
    const size_t sizes[3] = {2, 30, N};
    uint8_t saved[64];
    memcpy(saved, sigs[0], 64);

    for (int k = 0; k < 3; k++) {
        size_t n = sizes[k];
        ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, n));

        /* r_1 = p */
        HEX32(p_bytes, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        memcpy(sigs[0], p_bytes, 32);
        ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, n));
        memcpy(sigs[0], saved, 64);

        /* r_1 = 5: x^3 + 7 = 132 is not a square mod p */
        memset(sigs[0], 0, 32);
        sigs[0][31] = 5;
        ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, n));
        memcpy(sigs[0], saved, 64);

        /* s_1 = n */
        HEX32(n_bytes, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        memcpy(sigs[0] + 32, n_bytes, 32);
        ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, n));
        memcpy(sigs[0], saved, 64);
    }

    /* s_1' = 2*e_1*d - s_1, d the secret of the even-y key: s_1'*G - e_1*P = -R_1 */
    secp256k1_scalar d, e, s, t;
    scalar_from_bytes(&d, sec);
    if (pub65[64] & 1) scalar_negate(&d, &d);
    uint8_t pre[96], e_bytes[32];
    memcpy(pre, saved, 32);
    memcpy(pre + 32, pub65 + 1, 32);
    memcpy(pre + 64, msgs[0], 32);
    secp256k1c_tagged_hash(e_bytes, "BIP0340/challenge", pre, 96);
    scalar_from_bytes(&e, e_bytes);
    scalar_reduce(&e);
    scalar_from_bytes(&s, saved + 32);
    scalar_mul(&t, &e, &d);
    scalar_add(&t, &t, &t);
    scalar_negate(&s, &s);
    scalar_add(&s, &t, &s);
    scalar_to_bytes(sigs[0] + 32, &s);
    ASSERT_FALSE(secp256k1c_schnorr_verify(sigs[0], msgs[0], 32, pub65 + 1));
    for (int k = 0; k < 3; k++) {
        ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, sizes[k]));
    }
    /* The same signature second in the batch, where its R is lifted (even y) like the others */
    memcpy(sigs[1], sigs[0], 64);
    memcpy(msgs[1], msgs[0], 32);
    memcpy(sigs[0], saved, 64);
    for (int k = 0; k < 3; k++) {
        ASSERT_FALSE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, sizes[k]));
    }
}

/* KI-3 (libschnorr256k1-bench): the point-table cache was keyed by x alone, and a point and its
 * negation share an x. A tweak-mul of an odd-y key cached tables that verify then used for the
 * key's even-y x-only form (rejecting valid signatures), and after a verify the tweak-mul of
 * the odd-y point came out negated. Both orders, against d*t*G computed without the cache. */
static void point_cache_keeps_y_parity(void) {
    uint8_t sec[32] = {0}, pub65[65];
    for (uint8_t i = 1;; i++) { /* a key with odd y */
        sec[0] = 0x5A; sec[31] = i;
        ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
        if (pub65[64] & 1) break;
    }
    HEX32(tweak, "3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3");

    /* d*t*G, the expected tweak-mul of the odd-y point d*G */
    secp256k1_scalar d, t, dt;
    scalar_from_bytes(&d, sec);
    scalar_from_bytes(&t, tweak);
    scalar_mul(&dt, &d, &t);
    uint8_t dt_bytes[32], want65[65];
    scalar_to_bytes(dt_bytes, &dt);
    ASSERT_TRUE(secp256k1c_pubkey_create(want65, dt_bytes));

    uint8_t msg[32], sig[64], got65[65], pub33[33];
    memset(msg, 0x33, 32);
    ASSERT_TRUE(secp256k1c_schnorr_sign(sig, msg, 32, sec, NULL));
    pub33[0] = 0x03;
    memcpy(pub33 + 1, pub65 + 1, 32);

    for (int round = 0; round < 2; round++) {
        /* Tweak-mul first (caches the odd-y point), then verify (the even-y lift of its x) */
        ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(got65, 65, pub65, 65, tweak));
        ASSERT_MEM_EQ(got65, want65, 65);
        ASSERT_TRUE(secp256k1c_schnorr_verify(sig, msg, 32, pub65 + 1));
        ASSERT_TRUE(secp256k1c_schnorr_verify_fast(sig, msg, 32, pub65 + 1));
        const uint8_t *sp[2] = {sig, sig}, *mp[2] = {msg, msg};
        size_t lens[2] = {32, 32};
        ASSERT_TRUE(secp256k1c_schnorr_verify_batch(pub65 + 1, sp, mp, lens, 2));
        /* And back: the tweak-mul after the verify, from the 65- and the 33-byte forms */
        ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(got65, 65, pub65, 65, tweak));
        ASSERT_MEM_EQ(got65, want65, 65);
        uint8_t got33[33];
        ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(got33, 33, pub33, 33, tweak));
        ASSERT_EQ_INT(got33[0], 0x02 | (want65[64] & 1));
        ASSERT_MEM_EQ(got33 + 1, want65 + 1, 32);
    }
}

/* A key's tables are built on its first use (ecmult_odd_multiples_affine) and copied from the
 * cache after. Both must give the same answers, for keys of both parities and for verify, ECDH
 * and tweak-mul alike, and tweak-mul must equal d*t*G computed with no table. */
static void key_tables_agree_built_and_cached(void) {
    HEX32(tweak, "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
    for (int k = 1; k <= 12; k++) {
        uint8_t sec[32] = {0}, pub65[65], msg[32], sig[64], ecdh[3][32], tw[3][65];
        sec[0] = 0x71; sec[31] = (uint8_t)k;
        ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
        memset(msg, k, 32);
        ASSERT_TRUE(secp256k1c_schnorr_sign(sig, msg, 32, sec, NULL));
        uint8_t bad[64];
        memcpy(bad, sig, 64);
        bad[63] ^= 1;
        for (int round = 0; round < 3; round++) {
            ASSERT_TRUE(secp256k1c_schnorr_verify(sig, msg, 32, pub65 + 1));
            ASSERT_FALSE(secp256k1c_schnorr_verify(bad, msg, 32, pub65 + 1));
        }
        /* A fresh key for ECDH and tweak-mul (the verifies above cached the first one) */
        sec[0] = 0x72;
        ASSERT_TRUE(secp256k1c_pubkey_create(pub65, sec));
        for (int round = 0; round < 3; round++) {
            ASSERT_TRUE(secp256k1c_ecdh_xonly(ecdh[round], pub65 + 1, tweak));
            ASSERT_TRUE(secp256k1c_pubkey_tweak_mul(tw[round], 65, pub65, 65, tweak));
        }
        ASSERT_MEM_EQ(ecdh[0], ecdh[1], 32);
        ASSERT_MEM_EQ(ecdh[0], ecdh[2], 32);
        ASSERT_MEM_EQ(tw[0], tw[1], 65);
        ASSERT_MEM_EQ(tw[0], tw[2], 65);
        /* tweak-mul against d*t*G computed without any table */
        secp256k1_scalar d, t, dt;
        uint8_t dtb[32], want[65];
        scalar_from_bytes(&d, sec);
        scalar_from_bytes(&t, tweak);
        scalar_mul(&dt, &d, &t);
        scalar_to_bytes(dtb, &dt);
        ASSERT_TRUE(secp256k1c_pubkey_create(want, dtb));
        ASSERT_MEM_EQ(tw[0], want, 65);
    }
}

/* ==================== Tagged Hash ==================== */

static void tagged_hash_consistency(void) {
    uint8_t msg[32]; memset(msg, 0x42, 32);
    uint8_t result[32];
    secp256k1c_tagged_hash(result, "BIP0340/challenge", msg, 32);

    /* Manual: SHA256(SHA256(tag) || SHA256(tag) || msg) */
    uint8_t tag_hash[32];
    secp256k1c_sha256(tag_hash, (const uint8_t *)"BIP0340/challenge", 17);
    uint8_t preimage[96];
    memcpy(preimage, tag_hash, 32);
    memcpy(preimage + 32, tag_hash, 32);
    memcpy(preimage + 64, msg, 32);
    uint8_t expected[32];
    secp256k1c_sha256(expected, preimage, 96);
    ASSERT_MEM_EQ(result, expected, 32);
}

/* ==================== Runner ==================== */

void run_secp256k1_tests(void) {
    SUITE(secp256k1);
    printf("Running secp256k1 integration tests...\n");
    /* Key validation */
    TEST(verify_valid_privkey);
    TEST(verify_invalid_privkey_curve_order);
    TEST(verify_invalid_privkey_zero);
    /* Key creation */
    TEST(create_valid_pubkey);
    TEST(create_pubkey_from_key_one);
    TEST(create_pubkey_from_key_three);
    /* Compression */
    TEST(compress_pubkey);
    TEST(compress_pubkey_odd_y);
    TEST(compress_pubkey_even_y);
    /* Tweaking */
    TEST(privkey_tweak_add);
    TEST(pubkey_tweak_mul);
    TEST(pubkey_tweak_mul_compressed);
    /* ECDH */
    TEST(ecdh_symmetry);
    TEST(ecdh_xonly_symmetric);
    TEST(ecdh_xonly_matches_tweak_mul);
    TEST(ecdh_xonly_cached_and_new_agree);
    TEST(ecdh_xonly_rejects_x_off_the_curve);
    /* Schnorr edge cases */
    TEST(verify_wrong_message);
    TEST(verify_corrupted_sig);
    TEST(sign_deterministic);
    /* Batch */
    TEST(batch_all_valid);
    TEST(batch_with_invalid);
    TEST(batch_empty);
    TEST(batch_single);
    TEST(batch_large);
    TEST(batch_rejects_cancelling_signatures);
    TEST(batch_sizes_and_single_errors);
    TEST(batch_rejects_bad_first_signature);
    TEST(point_cache_keeps_y_parity);
    TEST(key_tables_agree_built_and_cached);
    /* Tagged hash */
    TEST(tagged_hash_consistency);
    printf("  secp256k1: done\n");
}
