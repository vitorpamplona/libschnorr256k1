/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * x86_64 SHA-NI transform. Compiled in isolation with -msha -mssse3 -msse4.1
 * so SHA-NI intrinsics never leak into TUs that the runtime dispatcher might
 * skip on CPUs lacking the extension.
 */
#include "sha256_hw.h"

#if defined(__x86_64__) || defined(_M_X64)

#include <immintrin.h>

void sha256_transform_shani(uint32_t state[8], const uint8_t block[64]) {
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Load state */
    __m128i STATE0 = _mm_loadu_si128((const __m128i*)&state[0]);
    __m128i STATE1 = _mm_loadu_si128((const __m128i*)&state[4]);

    /* Shuffle for SHA-NI format: STATE0=[A,B,E,F], STATE1=[C,D,G,H] */
    __m128i TMP = _mm_shuffle_epi32(STATE0, 0xB1); /* [B,A,F,E] */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);       /* [H,G,D,C] */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);       /* [A,B,E,F] */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);    /* [C,D,G,H] */

    __m128i ABEF_SAVE = STATE0;
    __m128i CDGH_SAVE = STATE1;

    /* Load message */
    __m128i MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block +  0)), MASK);
    __m128i MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block + 16)), MASK);
    __m128i MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block + 32)), MASK);
    __m128i MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block + 48)), MASK);

    static const uint32_t K[64] __attribute__((aligned(16))) = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    __m128i MSG;

    /* Rounds 0-3 */
    MSG = _mm_add_epi32(MSG0, _mm_load_si128((const __m128i*)&K[0]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 4-7 */
    MSG = _mm_add_epi32(MSG1, _mm_load_si128((const __m128i*)&K[4]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG = _mm_add_epi32(MSG2, _mm_load_si128((const __m128i*)&K[8]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    MSG = _mm_add_epi32(MSG3, _mm_load_si128((const __m128i*)&K[12]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    __m128i TMP2 = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP2);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 through 60-63 (unrolled loop) */
    #define SHA_ROUND(i, m0, m1, m2, m3) do { \
        MSG = _mm_add_epi32(m0, _mm_load_si128((const __m128i*)&K[i])); \
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG); \
        TMP2 = _mm_alignr_epi8(m0, m3, 4); \
        m1 = _mm_add_epi32(m1, TMP2); \
        m1 = _mm_sha256msg2_epu32(m1, m0); \
        MSG = _mm_shuffle_epi32(MSG, 0x0E); \
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG); \
        m3 = _mm_sha256msg1_epu32(m3, m0); \
    } while(0)

    SHA_ROUND(16, MSG0, MSG1, MSG2, MSG3);
    SHA_ROUND(20, MSG1, MSG2, MSG3, MSG0);
    SHA_ROUND(24, MSG2, MSG3, MSG0, MSG1);
    SHA_ROUND(28, MSG3, MSG0, MSG1, MSG2);
    SHA_ROUND(32, MSG0, MSG1, MSG2, MSG3);
    SHA_ROUND(36, MSG1, MSG2, MSG3, MSG0);
    SHA_ROUND(40, MSG2, MSG3, MSG0, MSG1);
    SHA_ROUND(44, MSG3, MSG0, MSG1, MSG2);
    SHA_ROUND(48, MSG0, MSG1, MSG2, MSG3);
    SHA_ROUND(52, MSG1, MSG2, MSG3, MSG0);

    #undef SHA_ROUND

    /* Rounds 56-59 */
    MSG = _mm_add_epi32(MSG2, _mm_load_si128((const __m128i*)&K[56]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP2 = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP2);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 60-63 */
    MSG = _mm_add_epi32(MSG3, _mm_load_si128((const __m128i*)&K[60]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Add saved state */
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    /* Unshuffle */
    TMP = _mm_shuffle_epi32(STATE0, 0x1B);          /* [F,E,B,A] */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);       /* [D,C,H,G] */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);    /* [A,B,C,D] */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);       /* [E,F,G,H] */

    _mm_storeu_si128((__m128i*)&state[0], STATE0);
    _mm_storeu_si128((__m128i*)&state[4], STATE1);
}

#endif /* x86_64 */
