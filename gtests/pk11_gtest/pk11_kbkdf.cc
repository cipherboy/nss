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
    uint8_t key[AES_128_KEY_LENGTH] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE,
                                       0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
                                       0x09, 0xCF, 0x4F, 0x3C};

    SECItem key_item = {siBuffer, key, sizeof(key)/sizeof(key[0])};
    ScopedPK11SymKey p11_key = ImportKey(CKM_AES_CMAC, &key_item);

    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, 8};
    CK_SP800_108_DKM_LENGTH_FORMAT dkm = { CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS, CK_FALSE, 8 };

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, &iterator, sizeof(iterator) },
      { CK_SP800_108_DKM_LENGTH, &dkm, sizeof(dkm) }
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

    PK11SymKey *result = PK11_Derive(p11_key.get(), CKM_SP800_108_COUNTER_KDF, &kdfItem, CKM_AES_CBC, CKA_ENCRYPT, AES_128_KEY_LENGTH);

    if (result == NULL) {
      fprintf(stderr, "Error: %u - %s - %s\n", PORT_GetError(), PORT_ErrorToName(PORT_GetError()), PORT_ErrorToString(PORT_GetError()));
    }

    assert(result != NULL);
  }
};

TEST_F(Pkcs11KbkdfTest, TestPkcs11v3SampleCounterModeKdf) {
    RunTest();
}
}
