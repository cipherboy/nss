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
#include "pk11_kbkdf_feedbacknocounterfixed.h"
#include "pk11_kbkdf_feedbackcounterbeforeiter.h"
#include "pk11_kbkdf_feedbackcounterafteriter.h"
#include "pk11_kbkdf_feedbackcounterafterfixed.h"
#include "pk11_kbkdf_pipelinecounterbeforeiter.h"
#include "pk11_kbkdf_pipelinecounterafteriter.h"
#include "pk11_kbkdf_pipelinecounterafterfixed.h"

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

  void RunCounterKDF(CK_MECHANISM_TYPE prf_mech, CK_SP800_108_KDF_PARAMS_PTR kdf_params, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *expected) {
    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    /* Build our SECItem with our passed parameters. */
    ASSERT_NE(kdf_params, nullptr);
    SECItem params_item = { siBuffer, (unsigned char *)kdf_params, sizeof(*kdf_params) };

    /* Validate that our output is an even number of bytes. */
    ASSERT_EQ((output_bitlen % 8), 0u);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), CKM_SP800_108_COUNTER_KDF, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(PK11_ExtractKeyValue(result.get()), SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    ASSERT_NE(actual_item, nullptr);

    /* Wrap our expected output in a SECItem for easy comparisons. */
    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    ASSERT_EQ(SECITEM_CompareItem(actual_item, &expected_item), 0);
  }

  void RunFeedbackKDF(CK_MECHANISM_TYPE prf_mech, CK_SP800_108_FEEDBACK_KDF_PARAMS_PTR kdf_params, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *expected) {
    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    /* Build our SECItem with our passed parameters. */
    ASSERT_NE(kdf_params, nullptr);
    SECItem params_item = { siBuffer, (unsigned char *)kdf_params, sizeof(*kdf_params) };

    /* Validate that our output is an even number of bytes. */
    ASSERT_EQ(output_bitlen % 8, 0u);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), CKM_SP800_108_FEEDBACK_KDF, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(PK11_ExtractKeyValue(result.get()), SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    ASSERT_NE(actual_item, nullptr);

    /* Wrap our expected output in a SECItem for easy comparisons. */
    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    ASSERT_EQ(SECITEM_CompareItem(actual_item, &expected_item), 0);
  }

  void RunPipelineKDF(CK_MECHANISM_TYPE prf_mech, CK_SP800_108_KDF_PARAMS_PTR kdf_params, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *expected) {
    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    /* Build our SECItem with our passed parameters. */
    ASSERT_NE(kdf_params, nullptr);
    SECItem params_item = { siBuffer, (unsigned char *)kdf_params, sizeof(*kdf_params) };

    /* Validate that our output is an even number of bytes. */
    ASSERT_EQ((output_bitlen % 8), 0u);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), CKM_SP800_108_DOUBLE_PIPELINE_KDF, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(PK11_ExtractKeyValue(result.get()), SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    ASSERT_NE(actual_item, nullptr);

    /* Wrap our expected output in a SECItem for easy comparisons. */
    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    ASSERT_EQ(SECITEM_CompareItem(actual_item, &expected_item), 0);
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

    RunCounterKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
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

    RunCounterKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
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

    RunCounterKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunFeedbackNoCounterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Feedback mode tests with fixed input block data using the following
     * setup:
     *
     *  - First the chaining value.
     *  - Then a fixed byte array (fixed_input).
     *  - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */
    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len }
    };

    CK_SP800_108_FEEDBACK_KDF_PARAMS kdf_params = {
      prf_mech,
      2,
      dataParams,
      iv_len,
      iv,
      0,
      NULL
    };

    RunFeedbackKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunFeedbackCounterBeforeIterTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Feedback mode tests with fixed input block data using the following
     * setup:
     *
     *  - First an optional iteration variable.
     *  - Then the chaining value.
     *  - Then a fixed byte array (fixed_input).
     *  - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */
    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_OPTIONAL_COUNTER, &iterator, sizeof(iterator) },
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len }
    };

    CK_SP800_108_FEEDBACK_KDF_PARAMS kdf_params = {
      prf_mech,
      3,
      dataParams,
      iv_len,
      iv,
      0,
      NULL
    };

    RunFeedbackKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunFeedbackCounterAfterIterTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Feedback mode tests with fixed input block data using the following
     * setup:
     *
     *  - First the chaining value.
     *  - Then an optional iteration variable.
     *  - Then a fixed byte array (fixed_input).
     *  - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */
    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_OPTIONAL_COUNTER, &iterator, sizeof(iterator) },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len }
    };

    CK_SP800_108_FEEDBACK_KDF_PARAMS kdf_params = {
      prf_mech,
      3,
      dataParams,
      iv_len,
      iv,
      0,
      NULL
    };

    RunFeedbackKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunFeedbackCounterAfterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Feedback mode tests with fixed input block data using the following
     * setup:
     *
     *  - First the chaining value.
     *  - Then a fixed byte array (fixed_input).
     *  - Then an optional iteration variable.
     *  - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */
    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len },
      { CK_SP800_108_OPTIONAL_COUNTER, &iterator, sizeof(iterator) }
    };

    CK_SP800_108_FEEDBACK_KDF_PARAMS kdf_params = {
      prf_mech,
      3,
      dataParams,
      iv_len,
      iv,
      0,
      NULL
    };

    RunFeedbackKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunPipelineCounterBeforeIterTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Feedback mode tests with fixed input block data using the following
     * setup:
     *
     *  - First an optional iteration variable.
     *  - Then the chaining value.
     *  - Then a fixed byte array (fixed_input).
     *  - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */
    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_OPTIONAL_COUNTER, &iterator, sizeof(iterator) },
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len }
    };

    CK_SP800_108_KDF_PARAMS kdf_params = {
      prf_mech,
      3,
      dataParams,
      0,
      NULL
    };

    RunPipelineKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunPipelineCounterAfterIterTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Feedback mode tests with fixed input block data using the following
     * setup:
     *
     *  - First the chaining value.
     *  - Then an optional iteration variable.
     *  - Then a fixed byte array (fixed_input).
     *  - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */
    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_OPTIONAL_COUNTER, &iterator, sizeof(iterator) },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len }
    };

    CK_SP800_108_KDF_PARAMS kdf_params = {
      prf_mech,
      3,
      dataParams,
      0,
      NULL
    };

    RunPipelineKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunPipelineCounterAfterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    /* Feedback mode tests with fixed input block data using the following
     * setup:
     *
     *  - First the chaining value.
     *  - Then a fixed byte array (fixed_input).
     *  - Then an optional iteration variable.
     *  - No other data to the PRF.
     *
     * This generates an output of size (output_bitlen), which is compared
     * against (expected).
     */
    CK_SP800_108_COUNTER_FORMAT iterator = {CK_FALSE, counter_bitlen};

    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len },
      { CK_SP800_108_OPTIONAL_COUNTER, &iterator, sizeof(iterator) }
    };

    CK_SP800_108_KDF_PARAMS kdf_params = {
      prf_mech,
      3,
      dataParams,
      0,
      NULL
    };

    RunPipelineKDF(prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }
};

/* == Counter Tests == */

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

/* == Feedback Tests == */

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPFeedbackNoCounterFixed) {
  for (size_t offset = 0; offset < PK11_KBKDFFeedbackNoCounterFixed_Len; offset++) {
    FeedbackNoCounterFixed test = PK11_KBKDFFeedbackNoCounterFixed[offset];
    RunFeedbackNoCounterFixedTest(test.prf_mech, test.output_bitlen, test.key, test.key_len, test.iv, test.iv_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPFeedbackCounterBeforeIter) {
  for (size_t offset = 0; offset < PK11_KBKDFFeedbackCounterBeforeIter_Len; offset++) {
    FeedbackCounterBeforeIter test = PK11_KBKDFFeedbackCounterBeforeIter[offset];
    RunFeedbackCounterBeforeIterTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.iv, test.iv_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPFeedbackCounterAfterIter) {
  for (size_t offset = 0; offset < PK11_KBKDFFeedbackCounterAfterIter_Len; offset++) {
    FeedbackCounterAfterIter test = PK11_KBKDFFeedbackCounterAfterIter[offset];
    RunFeedbackCounterAfterIterTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.iv, test.iv_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPFeedbackCounterAfterFixed) {
  for (size_t offset = 0; offset < PK11_KBKDFFeedbackCounterAfterFixed_Len; offset++) {
    FeedbackCounterAfterFixed test = PK11_KBKDFFeedbackCounterAfterFixed[offset];
    RunFeedbackCounterAfterFixedTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.iv, test.iv_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

/* == Double Pipeline Tests == */

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPPipelineCounterBeforeIter) {
  for (size_t offset = 0; offset < PK11_KBKDFPipelineCounterBeforeIter_Len; offset++) {
    PipelineCounterBeforeIter test = PK11_KBKDFPipelineCounterBeforeIter[offset];
    RunPipelineCounterBeforeIterTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPPipelineCounterAfterIter) {
  for (size_t offset = 0; offset < PK11_KBKDFPipelineCounterAfterIter_Len; offset++) {
    PipelineCounterAfterIter test = PK11_KBKDFPipelineCounterAfterIter[offset];
    RunPipelineCounterAfterIterTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPPipelineCounterAfterFixed) {
  for (size_t offset = 0; offset < PK11_KBKDFPipelineCounterAfterFixed_Len; offset++) {
    PipelineCounterAfterFixed test = PK11_KBKDFPipelineCounterAfterFixed[offset];
    RunPipelineCounterAfterFixedTest(test.prf_mech, test.counter_bitlen, test.output_bitlen, test.key, test.key_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

// Close the namespace
}
