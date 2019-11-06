/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
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

#include "pk11_kbkdf_counterbeforefixed.h"
#include "pk11_kbkdf_countermiddlefixed.h"
#include "pk11_kbkdf_counterafterfixed.h"

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

  void RunCounterBeforeFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Counter mode tests with CTRLOCATION=BEFORE_FIXED use the following
     * setup:
     *
     * - First the big-endian counter (counter_bitlen),
     * - Then a fixed byte array (fixed_input),
     * - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */

    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, &iterator, sizeof(iterator) },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len },
    };

    CK_SP800_108_KDF_PARAMS kdf_params =
    {
      prf_mech,
      2,
      dataParams,
      0,       /* no additional derived keys */
      NULL     /* no additional derived keys */
    };

    SECItem params_item = { siBuffer, (unsigned char *)&kdf_params, sizeof(kdf_params) };

    assert((output_bitlen % 8) == 0);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), CKM_SP800_108_COUNTER_KDF, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
    if (result.get() == NULL) {
      fprintf(stderr, "Error: %u - %s - %s\n", PORT_GetError(), PORT_ErrorToName(PORT_GetError()), PORT_ErrorToString(PORT_GetError()));
    }
    assert(result != NULL);

    assert(PK11_ExtractKeyValue(result.get()) == SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    assert(actual_item != NULL);

    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    assert(SECITEM_CompareItem(actual_item, &expected_item) == 0);
  }

  void RunCounterMiddleFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *before_fixed_input, uint32_t before_fixed_input_len, uint8_t *after_fixed_input, uint32_t after_fixed_input_len, uint8_t *expected) {
    /* Counter mode tests with CTRLOCATION=MIDDLE_FIXED use the following
     * setup:
     *
     * - First a fixed byte array (before_fixed_input),
     * - Then the big-endian counter (counter_bitlen),
     * - Then a fixed byte array (after_fixed_input),
     * - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */

    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_BYTE_ARRAY, before_fixed_input, before_fixed_input_len },
      { CK_SP800_108_ITERATION_VARIABLE, &iterator, sizeof(iterator) },
      { CK_SP800_108_BYTE_ARRAY, after_fixed_input, after_fixed_input_len },
    };

    CK_SP800_108_KDF_PARAMS kdf_params =
    {
      prf_mech,
      3,
      dataParams,
      0,       /* no additional derived keys */
      NULL     /* no additional derived keys */
    };

    SECItem params_item = { siBuffer, (unsigned char *)&kdf_params, sizeof(kdf_params) };

    assert((output_bitlen % 8) == 0);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), CKM_SP800_108_COUNTER_KDF, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
    if (result.get() == NULL) {
      fprintf(stderr, "Error: %u - %s - %s\n", PORT_GetError(), PORT_ErrorToName(PORT_GetError()), PORT_ErrorToString(PORT_GetError()));
    }
    assert(result != NULL);

    assert(PK11_ExtractKeyValue(result.get()) == SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    assert(actual_item != NULL);

    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    assert(SECITEM_CompareItem(actual_item, &expected_item) == 0);
  }

  void RunCounterAfterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Counter mode tests with CTRLOCATION=AFTER_FIXED use the following
     * setup:
     *
     * - First a fixed byte array (fixed_input),
     * - Then the big-endian counter (counter_bitlen),
     * - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */

    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len },
      { CK_SP800_108_ITERATION_VARIABLE, &iterator, sizeof(iterator) },
    };

    CK_SP800_108_KDF_PARAMS kdf_params =
    {
      prf_mech,
      2,
      dataParams,
      0,       /* no additional derived keys */
      NULL     /* no additional derived keys */
    };

    SECItem params_item = { siBuffer, (unsigned char *)&kdf_params, sizeof(kdf_params) };

    assert((output_bitlen % 8) == 0);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), CKM_SP800_108_COUNTER_KDF, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
    if (result.get() == NULL) {
      fprintf(stderr, "Error: %u - %s - %s\n", PORT_GetError(), PORT_ErrorToName(PORT_GetError()), PORT_ErrorToString(PORT_GetError()));
    }
    assert(result != NULL);

    assert(PK11_ExtractKeyValue(result.get()) == SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    assert(actual_item != NULL);

    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    assert(SECITEM_CompareItem(actual_item, &expected_item) == 0);
  }
};

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPCounterBeforeFixed) {
  for (size_t offset = 0; offset < PK11_KBKDFCounterBeforeFixed_Len; offset++) {
    CounterBeforeFixed test = PK11_KBKDFCounterBeforeFixed[offset];
    RunCounterBeforeFixedTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPCounterMiddleFixed) {
  for (size_t offset = 0; offset < PK11_KBKDFCounterMiddleFixed_Len; offset++) {
    CounterMiddleFixed test = PK11_KBKDFCounterMiddleFixed[offset];
    RunCounterMiddleFixedTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.before_fixed_input, test.before_fixed_input_len, test.after_fixed_input, test.after_fixed_input_len, test.expected);
  }
}

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPCounterAfterFixed) {
  for (size_t offset = 0; offset < PK11_KBKDFCounterAfterFixed_Len; offset++) {
    CounterAfterFixed test = PK11_KBKDFCounterAfterFixed[offset];
    RunCounterAfterFixedTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}
}
