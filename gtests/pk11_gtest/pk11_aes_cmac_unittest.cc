/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>
#include "nss.h"
#include "pk11pub.h"
#include "secerr.h"
#include "sechash.h"

#include "blapi.h"

#include "gtest/gtest.h"
#include "util.h"

namespace nss_test {

class Pkcs11AesCmacTest : public ::testing::Test {
    protected:
        SECItem *wrap(unsigned char *data, unsigned int data_len) {
            SECItem *key_item = (SECItem *)calloc(1, sizeof(SECItem));
            key_item->type = siBuffer;
            key_item->data = data;
            key_item->len = data_len;
            return key_item;
        }

        PK11SymKey *ImportKey(PK11SlotInfo *slot, CK_MECHANISM_TYPE mech,
                              SECItem *key_item) {
            PK11SymKey *result = PK11_ImportSymKey(slot, mech,
                                                   PK11_OriginUnwrap,
                                                   CKA_SIGN, key_item,
                                                   nullptr);
            return result;
        }

        bool Compare(unsigned char *actual, unsigned char *expected,
                     unsigned int length) {
            if (strncmp((char *)actual, (char *)expected, length) != 0) {
                fprintf(stderr, "Differed in value!\nActual: ");
                for (unsigned int i = 0; i < length; i++) {
                  fprintf(stderr, "%02X", actual[i]);
                }
                fprintf(stderr, "\nExpected: ");
                for (unsigned int i = 0; i < length; i++) {
                  fprintf(stderr, "%02X", expected[i]);
                }
                fprintf(stderr, "\n");
                return false;
            }
            return true;
        }

        void RunTest(unsigned char *key, unsigned int key_len,
                     unsigned char *data, unsigned int data_len,
                     unsigned char *expected, unsigned int expected_len) {
            // Create SECItems for everything...
            unsigned char *output = (unsigned char *)calloc(expected_len,
                                                            sizeof(unsigned char));
            SECItem *key_item = wrap(key, key_len);
            SECItem *output_item = wrap(output, expected_len);
            SECItem *data_item = wrap(data, data_len);
            ASSERT_NE(nullptr, output);
            ASSERT_NE(nullptr, key_item);
            ASSERT_NE(nullptr, output_item);
            ASSERT_NE(nullptr, data_item);

            // Do the PKCS #11 stuff...
            PK11SlotInfo *p11_slot = PK11_GetInternalSlot();
            ASSERT_NE(nullptr, p11_slot);

            PK11SymKey *p11_key = ImportKey(p11_slot, CKM_AES_CMAC, key_item);
            ASSERT_NE(nullptr, p11_key);

            SECStatus ret = PK11_SignWithSymKey(p11_key, CKM_AES_CMAC, NULL,
                                                output_item, data_item);

            // Verify the result...
            ASSERT_EQ(SECSuccess, ret);
            ASSERT_EQ(true, Compare(output_item->data, expected, expected_len));

            // Clean up after ourselves...
            PK11_FreeSymKey(p11_key);
            PK11_FreeSlot(p11_slot);
            free(key_item);
            free(output_item);
            free(data_item);
            free(output);
        }
};

// Sanity check of the PKCS #11 API only. Extensive tests conducted
// as part of gtests/freebl_gtest/cmac_unittests.cc
TEST_F(Pkcs11AesCmacTest, test_aes128_nist_example_1) {
    unsigned char key[AES_128_KEY_LENGTH] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    unsigned char known[AES_BLOCK_SIZE] = {0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75, 0x67, 0x46};

    RunTest(key, AES_128_KEY_LENGTH, NULL, 0, known, AES_BLOCK_SIZE);
}

}
