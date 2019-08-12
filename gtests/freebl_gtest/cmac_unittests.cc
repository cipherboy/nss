// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

#include "gtest/gtest.h"

#include <stdint.h>
#include <memory>

#include "blapi.h"
#include "secitem.h"
#include "freebl_scoped_ptrs.h"

class CMACTest : public ::testing::Test {
    protected:
        bool Compare(const unsigned char *actual, const unsigned char *expected, unsigned int length) {
            return strncmp((const char *)actual, (const char *)expected, length) == 0;
        }
};

TEST_F(CMACTest, invalid_size) {
    ScopedCMACContext ctx(CMAC_Create(CMAC_AES, {0x00}, 1));
    ASSERT_EQ(ctx, nullptr);
}

TEST_F(CMACTest, right_size) {
    unsigned char *key = PORT_NewArray(unsigned char, AES_128_KEY_LENGTH);
    ScopedCMACContext ctx(CMAC_Create(CMAC_AES, key, AES_128_KEY_LENGTH));

    ASSERT_NE(ctx, nullptr);
    PORT_Free(key);
}

/* The following tests were taken from NIST's Cryptographic Standards and
 * Guidelines page for AES-CMAC Examples with Intermediate Values. These same
 * test vectors for AES-128 can be found in RFC 4493, section 4. */

const unsigned char kNistKeys[3][AES_256_KEY_LENGTH] = {
    {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
     0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
     0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4}
};
#define kNistKeyLengthsCount PR_ARRAY_SIZE(kNistKeys)
const unsigned int kNistKeyLengths[kNistKeyLengthsCount] = {
    AES_128_KEY_LENGTH,
    AES_192_KEY_LENGTH,
    AES_256_KEY_LENGTH
};

const unsigned char kNistPlaintext[64] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};
const unsigned int kNistPlaintextLengths[4] = {0, 16, 20, 64};
#define kNistPlaintextLengthsCount PR_ARRAY_SIZE(kNistPlaintextLengths)

const unsigned char kNistKnown[12][AES_BLOCK_SIZE] = {
    {0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75, 0x67, 0x46},
    {0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44, 0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28, 0x7C},
    {0x7D, 0x85, 0x44, 0x9E, 0xA6, 0xEA, 0x19, 0xC8, 0x23, 0xA7, 0xBF, 0x78, 0x83, 0x7D, 0xFA, 0xDE},
    {0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92, 0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C, 0xFE},
    {0xD1, 0x7D, 0xDF, 0x46, 0xAD, 0xAA, 0xCD, 0xE5, 0x31, 0xCA, 0xC4, 0x83, 0xDE, 0x7A, 0x93, 0x67},
    {0x9E, 0x99, 0xA7, 0xBF, 0x31, 0xE7, 0x10, 0x90, 0x06, 0x62, 0xF6, 0x5E, 0x61, 0x7C, 0x51, 0x84},
    {0x3D, 0x75, 0xC1, 0x94, 0xED, 0x96, 0x07, 0x04, 0x44, 0xA9, 0xFA, 0x7E, 0xC7, 0x40, 0xEC, 0xF8},
    {0xA1, 0xD5, 0xDF, 0x0E, 0xED, 0x79, 0x0F, 0x79, 0x4D, 0x77, 0x58, 0x96, 0x59, 0xF3, 0x9A, 0x11},
    {0x02, 0x89, 0x62, 0xF6, 0x1B, 0x7B, 0xF8, 0x9E, 0xFC, 0x6B, 0x55, 0x1F, 0x46, 0x67, 0xD9, 0x83},
    {0x28, 0xA7, 0x02, 0x3F, 0x45, 0x2E, 0x8F, 0x82, 0xBD, 0x4B, 0xF2, 0x8D, 0x8C, 0x37, 0xC3, 0x5C},
    {0x15, 0x67, 0x27, 0xDC, 0x08, 0x78, 0x94, 0x4A, 0x02, 0x3C, 0x1F, 0xE0, 0x3B, 0xAD, 0x6D, 0x93},
    {0xE1, 0x99, 0x21, 0x90, 0x54, 0x9F, 0x6E, 0xD5, 0x69, 0x6A, 0x2C, 0x05, 0x6C, 0x31, 0x54, 0x10}
};

TEST_F(CMACTest, test_aes_nist_aligned) {
    for (unsigned int key_index = 0; key_index < kNistKeyLengthsCount; key_index++) {
        ScopedCMACContext ctx(CMAC_Create(CMAC_AES, kNistKeys[key_index], kNistKeyLengths[key_index]));
        ASSERT_NE(ctx, nullptr);

        for (unsigned int plaintext_index = 0; plaintext_index < kNistPlaintextLengthsCount; plaintext_index++) {
            CMAC_Begin(ctx.get());

            unsigned int known_index = (key_index * kNistPlaintextLengthsCount) + plaintext_index;
            CMAC_Update(ctx.get(), kNistPlaintext, kNistPlaintextLengths[plaintext_index]);

            unsigned char output[AES_BLOCK_SIZE];
            CMAC_Finish(ctx.get(), output, NULL, AES_BLOCK_SIZE);

            ASSERT_TRUE(Compare(output, kNistKnown[known_index], AES_BLOCK_SIZE));
        }
    }
}

TEST_F(CMACTest, test_aes_nist_unaligned) {
    for (unsigned int key_index = 0; key_index < kNistKeyLengthsCount; key_index++) {
        unsigned int key_length = kNistKeyLengths[key_index];
        ScopedCMACContext ctx(CMAC_Create(CMAC_AES, kNistKeys[key_index], key_length));
        ASSERT_NE(ctx, nullptr);

        /* Skip the zero-length test. */
        for (unsigned int plaintext_index = 1; plaintext_index < kNistPlaintextLengthsCount; plaintext_index++) {
            unsigned int known_index = (key_index * kNistPlaintextLengthsCount) + plaintext_index;
            unsigned int plaintext_length = kNistPlaintextLengths[plaintext_index];

            /* Test all possible offsets and make sure that misaligned updates
             * produce the desired result. That is, do two updates:
             *  0      ... offset
             *  offset ... len - offset
             * and ensure the result is the same as doing one update. */
            for (unsigned int offset = 1; offset < plaintext_length; offset += 1) {
                CMAC_Begin(ctx.get());

                CMAC_Update(ctx.get(), kNistPlaintext, offset);
                CMAC_Update(ctx.get(), kNistPlaintext + offset, plaintext_length - offset);

                unsigned char output[AES_BLOCK_SIZE];
                CMAC_Finish(ctx.get(), output, NULL, AES_BLOCK_SIZE);

                ASSERT_TRUE(Compare(output, kNistKnown[known_index], AES_BLOCK_SIZE));
            }
        }
    }
}

TEST_F(CMACTest, test_aes_nist_truncated) {
    for (unsigned int key_index = 0; key_index < kNistKeyLengthsCount; key_index++) {
        unsigned int key_length = kNistKeyLengths[key_index];
        ScopedCMACContext ctx(CMAC_Create(CMAC_AES, kNistKeys[key_index], key_length));
        ASSERT_TRUE(ctx != nullptr);

        /* Skip the zero-length test. */
        for (unsigned int plaintext_index = 1; plaintext_index < kNistPlaintextLengthsCount; plaintext_index++) {
            unsigned int known_index = (key_index * kNistPlaintextLengthsCount) + plaintext_index;
            unsigned int plaintext_length = kNistPlaintextLengths[plaintext_index];

            /* Test truncated outputs to ensure that we always get the desired
             * values. */
            for (unsigned int out_len = 1; out_len < AES_BLOCK_SIZE; out_len += 1) {
                CMAC_Begin(ctx.get());

                CMAC_Update(ctx.get(), kNistPlaintext, plaintext_length);

                unsigned int actual_out_len = 0;
                unsigned char output[AES_BLOCK_SIZE];
                CMAC_Finish(ctx.get(), output, &actual_out_len, out_len);

                ASSERT_TRUE(actual_out_len == out_len);
                ASSERT_TRUE(Compare(output, kNistKnown[known_index], out_len));
            }
        }
    }
}
