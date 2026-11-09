/*
 * Copyright (c) 2025 Vitor Pamplona
 * Key parsing/serialization tests. Ported from KeyCodecTest.kt
 */
#include "test_framework.h"
#include "point.h"

/* ==================== liftX ==================== */

static void lift_x_generator(void) {
    secp256k1_fe x, y;
    ASSERT_TRUE(point_lift_x(&x, &y, &SECP256K1_G.x));
    ASSERT_TRUE(fe_equal(&x, &SECP256K1_G.x));
    ASSERT_TRUE(point_has_even_y(&y));
}

static void lift_x_invalid_field_element(void) {
    /* p itself is not a valid x */
    secp256k1_fe x, y;
    ASSERT_FALSE(point_lift_x(&x, &y, &FE_P));
}

static void lift_x_always_returns_even_y(void) {
    secp256k1_fe x, y;
    ASSERT_TRUE(point_lift_x(&x, &y, &SECP256K1_G.x));
    ASSERT_TRUE(point_has_even_y(&y));
}

/* ==================== hasEvenY ==================== */

static void has_even_y_for_even(void) {
    secp256k1_fe two = {{2, 0, 0, 0}};
    secp256k1_fe zero = FE_ZERO;
    ASSERT_TRUE(point_has_even_y(&two));
    ASSERT_TRUE(point_has_even_y(&zero));
}

static void has_even_y_for_odd(void) {
    secp256k1_fe one = FE_ONE;
    secp256k1_fe three = {{3, 0, 0, 0}};
    ASSERT_FALSE(point_has_even_y(&one));
    ASSERT_FALSE(point_has_even_y(&three));
}

/* ==================== parsePublicKey ==================== */

static void parse_compressed_even_y(void) {
    uint8_t compressed[33];
    point_serialize_compressed(compressed, &SECP256K1_G);
    ASSERT_EQ_INT(compressed[0], 0x02);

    secp256k1_ge parsed;
    ASSERT_TRUE(point_parse_pubkey(&parsed, compressed, 33));
    ASSERT_TRUE(fe_equal(&parsed.x, &SECP256K1_G.x));
    ASSERT_TRUE(fe_equal(&parsed.y, &SECP256K1_G.y));
}

static void parse_compressed_odd_y(void) {
    secp256k1_fe neg_gy;
    fe_negate(&neg_gy, &SECP256K1_G.y, 1);
    fe_normalize_full(&neg_gy);
    secp256k1_ge neg_g = {.x = SECP256K1_G.x, .y = neg_gy};

    uint8_t compressed[33];
    point_serialize_compressed(compressed, &neg_g);
    ASSERT_EQ_INT(compressed[0], 0x03);

    secp256k1_ge parsed;
    ASSERT_TRUE(point_parse_pubkey(&parsed, compressed, 33));
    ASSERT_TRUE(fe_equal(&parsed.x, &SECP256K1_G.x));
    ASSERT_TRUE(fe_equal(&parsed.y, &neg_gy));
}

static void parse_uncompressed(void) {
    uint8_t uncompressed[65];
    point_serialize_uncompressed(uncompressed, &SECP256K1_G);
    ASSERT_EQ_INT(uncompressed[0], 0x04);

    secp256k1_ge parsed;
    ASSERT_TRUE(point_parse_pubkey(&parsed, uncompressed, 65));
    ASSERT_TRUE(fe_equal(&parsed.x, &SECP256K1_G.x));
    ASSERT_TRUE(fe_equal(&parsed.y, &SECP256K1_G.y));
}

static void parse_invalid_sizes(void) {
    secp256k1_ge dummy;
    uint8_t buf[66];
    memset(buf, 0x02, sizeof(buf));
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf, 0));
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf, 10));
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf, 32));
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf, 34));
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf, 64));
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf, 66));
}

static void parse_invalid_prefix(void) {
    secp256k1_ge dummy;
    uint8_t buf33[33] = {0}; /* prefix 0x00 */
    uint8_t buf65[65] = {0}; /* prefix 0x00 */
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf33, 33));
    ASSERT_FALSE(point_parse_pubkey(&dummy, buf65, 65));
}

/* Keys off the curve or with a coordinate >= p are rejected: an off-curve point used to reach
 * the shared table cache under a real key's x, and invalid-curve points leak secret tweaks. */
static void parse_rejects_invalid_points(void) {
    secp256k1_ge dummy;
    uint8_t fake[65] = {0};
    fake[0] = 0x04;
    fake[1] = 0x01;
    fake[33] = 0x01;
    ASSERT_FALSE(point_parse_pubkey(&dummy, fake, 65)); /* (1, 1): off the curve */

    uint8_t g65[65];
    point_serialize_uncompressed(g65, &SECP256K1_G);
    ASSERT_TRUE(point_parse_pubkey(&dummy, g65, 65));
    g65[64] ^= 0x02; /* G's x with another y */
    ASSERT_FALSE(point_parse_pubkey(&dummy, g65, 65));
    g65[64] ^= 0x02;

    /* x = p + 1, congruent to 1, which is on the curve (8 is a square mod p): only the range
     * check rejects it, in both encodings */
    static const uint8_t P_PLUS_1[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x30};
    uint8_t one33[33] = {0x02};
    one33[32] = 1;
    secp256k1_ge one;
    ASSERT_TRUE(point_parse_pubkey(&one, one33, 33));
    uint8_t c33[33] = {0x02};
    memcpy(c33 + 1, P_PLUS_1, 32);
    ASSERT_FALSE(point_parse_pubkey(&dummy, c33, 33));
    uint8_t one65[65];
    point_serialize_uncompressed(one65, &one);
    ASSERT_TRUE(point_parse_pubkey(&dummy, one65, 65));
    memcpy(one65 + 1, P_PLUS_1, 32);
    ASSERT_FALSE(point_parse_pubkey(&dummy, one65, 65));
}

/* Valid points whose y is small, so y^2 and x^3 + 7 are small mod p: the on-curve check must
 * compare them reduced (libschnorr256k1-kotlin's 65-byte parser rejected these). */
static void parse_accepts_small_y_points(void) {
    static const char *KEYS[4] = {
        "041fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff5070000000000000000000000000000000000000000000000000000000000000001",
        "04c8b492e17665b9e65e4a124661e1103f1aebfcc849dcd94f7688dcf149f6f4f20000000000000000000000000000000000000000000000000000000000000006",
        "04a95c7e1d4c5db1863b7c6fb26ac231479ff552c18707b69a9ac6bf9c3676f31b000000000000000000000000000000000000000000000000000000000000000b",
        "04c2b84dcef67220199a187064a65579cad41a3345bcf6974fe3a153128b81ca10000000000000000000000000000000000000000000000000000000000000000d",
    };
    for (int i = 0; i < 4; i++) {
        uint8_t key[65], c33[33];
        hex_to_bytes(key, KEYS[i], 65);
        secp256k1_ge pt;
        ASSERT_TRUE(point_parse_pubkey(&pt, key, 65));
        ASSERT_TRUE(secp256k1c_pubkey_compress(c33, key));
        ASSERT_TRUE(point_parse_pubkey(&pt, c33, 33));
    }
}

/* ==================== Round-trips ==================== */

static void compress_decompress_roundtrip(void) {
    uint8_t compressed[33];
    point_serialize_compressed(compressed, &SECP256K1_G);

    secp256k1_ge parsed;
    ASSERT_TRUE(point_parse_pubkey(&parsed, compressed, 33));

    uint8_t recompressed[33];
    point_serialize_compressed(recompressed, &parsed);
    ASSERT_MEM_EQ(compressed, recompressed, 33);
}

static void uncompressed_roundtrip(void) {
    uint8_t uncompressed[65];
    point_serialize_uncompressed(uncompressed, &SECP256K1_G);

    secp256k1_ge parsed;
    ASSERT_TRUE(point_parse_pubkey(&parsed, uncompressed, 65));

    uint8_t reser[65];
    point_serialize_uncompressed(reser, &parsed);
    ASSERT_MEM_EQ(uncompressed, reser, 65);
}

/* ==================== Runner ==================== */

void run_key_codec_tests(void) {
    SUITE(key_codec);
    printf("Running key codec tests...\n");
    /* liftX */
    TEST(lift_x_generator);
    TEST(lift_x_invalid_field_element);
    TEST(lift_x_always_returns_even_y);
    /* hasEvenY */
    TEST(has_even_y_for_even);
    TEST(has_even_y_for_odd);
    /* Parsing */
    TEST(parse_compressed_even_y);
    TEST(parse_compressed_odd_y);
    TEST(parse_uncompressed);
    TEST(parse_invalid_sizes);
    TEST(parse_invalid_prefix);
    TEST(parse_rejects_invalid_points);
    TEST(parse_accepts_small_y_points);
    /* Round-trips */
    TEST(compress_decompress_roundtrip);
    TEST(uncompressed_roundtrip);
    printf("  Key codec: done\n");
}
