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
#include "stdio.h"

#include "blapi.h"

#include "gtest/gtest.h"
#include "nss_scoped_ptrs.h"
#include "util.h"

#define DIM(a) (sizeof((a))/sizeof((a)[0]))

namespace nss_test {
class Pkcs11KbkdfTest : public ::testing::Test {
 protected:
  ScopedPK11SymKey ImportKey(CK_MECHANISM_TYPE mech, SECItem *key_item) {
    ScopedPK11SlotInfo slot(PK11_GetInternalSlot());
    if (!slot) {
      ADD_FAILURE() << "Can't get slot";
      return nullptr;
    }

    ScopedPK11SymKey result(PK11_ImportSymKey(
        slot.get(), mech, PK11_OriginUnwrap, CKA_SIGN, key_item, nullptr));

    return result;
  }

  void RunTest(void) {
    uint8_t key[AES_128_KEY_LENGTH] = {0xdf, 0xf1, 0xe5, 0x0a, 0xc0, 0xb6, 0x9d, 0xc4, 0x0f, 0x10, 0x51, 0xd4, 0x6c, 0x2b, 0x06, 0x9c};
    uint8_t out_key[AES_128_KEY_LENGTH] = {0x8b, 0xe8, 0xf0, 0x86, 0x9b, 0x3c, 0x0b, 0xa9, 0x7b, 0x71, 0x86, 0x3d, 0x1b, 0x9f, 0x78, 0x13};

    uint8_t fixed_input[60] = {0xc1, 0x6e, 0x6e, 0x02, 0xc5, 0xa3, 0xdc, 0xc8, 0xd7, 0x8b, 0x9a, 0xc1, 0x30, 0x68, 0x77, 0x76, 0x13, 0x10, 0x45, 0x5b, 0x4e, 0x41, 0x46, 0x99, 0x51, 0xd9, 0xe6, 0xc2, 0x24, 0x5a, 0x06, 0x4b, 0x33, 0xfd, 0x8c, 0x3b, 0x01, 0x20, 0x3a, 0x78, 0x24, 0x48, 0x5b, 0xf0, 0xa6, 0x40, 0x60, 0xc4, 0x64, 0x8b, 0x70, 0x7d, 0x26, 0x07, 0x93, 0x56, 0x99, 0x31, 0x6e, 0xa5};

    SECItem key_item = {siBuffer, key, sizeof(key)/sizeof(key[0])};
    ScopedPK11SymKey p11_key = ImportKey(CKM_AES_CMAC, &key_item);

    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, 8};
    /* CK_SP800_108_DKM_LENGTH_FORMAT dkm = { CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, CK_FALSE, 8 }; */

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, &iterator, sizeof(iterator) },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, 60 },
    };

    CK_SP800_108_KDF_PARAMS kdfParams =
    {
      CKM_AES_CMAC,
      2,
      dataParams,
      0,       /* no additional derived keys */
      NULL     /* no additional derived keys */
    };

    SECItem kdfItem = { siBuffer, (unsigned char *)&kdfParams, sizeof(kdfParams) };

    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), CKM_SP800_108_COUNTER_KDF, &kdfItem, CKM_AES_CBC, CKA_ENCRYPT, AES_128_KEY_LENGTH));

    if (result.get() == NULL) {
      fprintf(stderr, "Error: %u - %s - %s\n", PORT_GetError(), PORT_ErrorToName(PORT_GetError()), PORT_ErrorToString(PORT_GetError()));
    }

    assert(result != NULL);

    assert(PK11_ExtractKeyValue(result.get()) == SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());

    if (actual_item == NULL) {
      fprintf(stderr, "Error: %u - %s - %s\n", PORT_GetError(), PORT_ErrorToName(PORT_GetError()), PORT_ErrorToString(PORT_GetError()));
    }

    assert(actual_item != NULL);

    assert(actual_item->len == AES_128_KEY_LENGTH);

    for (size_t i = 0; i < AES_128_KEY_LENGTH; i++) {
        assert(actual_item->data[i] == out_key[i]);
    }
  }
};

TEST_F(Pkcs11KbkdfTest, TestPkcs11v3SampleCounterModeKdf) {
    RunTest();
}
}
