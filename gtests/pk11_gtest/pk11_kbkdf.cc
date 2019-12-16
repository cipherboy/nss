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

/* == Counter mode NIST CAVP test vectors == */
#include "pk11_kbkdf_counterbeforefixed.h"
#include "pk11_kbkdf_countermiddlefixed.h"
#include "pk11_kbkdf_counterafterfixed.h"

/* == Feedback mode NIST CAVP test vectors == */
#include "pk11_kbkdf_feedbacknocounterfixed.h"
#include "pk11_kbkdf_feedbackcounterbeforeiter.h"
#include "pk11_kbkdf_feedbackcounterafteriter.h"
#include "pk11_kbkdf_feedbackcounterafterfixed.h"

/* == Pipeline mode CAVP test vectors == */
#include "pk11_kbkdf_pipelinenocounterfixed.h"
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

  size_t GetPRFSize(CK_MECHANISM_TYPE prf_mech, size_t key_len) {
    switch (prf_mech) {
      case CKM_AES_CMAC:
        return key_len;
      case CKM_SHA_1_HMAC:
        return 160/8;
      case CKM_SHA224_HMAC:
        return 224/8;
      case CKM_SHA384_HMAC:
        return 384/8;
      case CKM_SHA512_HMAC:
        return 512/8;
    }

    return 0;
  }

  void RunKDF(CK_MECHANISM_TYPE kdf_mech, CK_MECHANISM_TYPE prf_mech, CK_SP800_108_KDF_PARAMS_PTR kdf_params, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *expected) {
    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    /* Build our SECItem with our passed parameters. */
    ASSERT_NE(kdf_params, nullptr);
    SECItem params_item = { siBuffer, (unsigned char *)kdf_params, sizeof(*kdf_params) };

    /* Validate that our output is an even number of bytes. */
    ASSERT_EQ((output_bitlen % 8), 0u);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), kdf_mech, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(PK11_ExtractKeyValue(result.get()), SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    ASSERT_NE(actual_item, nullptr);

    /* Wrap our expected output in a SECItem for easy comparisons. */
    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    ASSERT_EQ(SECITEM_CompareItem(actual_item, &expected_item), 0);
  }

  void RunKDFAdditionalKeys(CK_MECHANISM_TYPE kdf_mech, CK_MECHANISM_TYPE prf_mech, CK_SP800_108_KDF_PARAMS_PTR kdf_params, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *expected) {
    SECItem key_item = {siBuffer, key, key_len};
    ScopedPK11SymKey p11_key = ImportKey(prf_mech, &key_item);

    size_t mac_size = GetPRFSize(prf_mech, key_len);

    CK_ULONG derived_length = 0;
    CK_KEY_TYPE ck_generic = CKK_GENERIC_SECRET;
    CK_OBJECT_CLASS ck_class = CKO_SECRET_KEY;

    CK_ATTRIBUTE derived_template[] = {
      { CKA_CLASS, &ck_class, sizeof(ck_class) },
      { CKA_KEY_TYPE, &ck_generic, sizeof(ck_generic) },
      { CKA_VALUE_LEN, &derived_length, sizeof(derived_length) }
    };

    CK_OBJECT_HANDLE key_handle;
    CK_DERIVED_KEY derived_key = {
      derived_template,
      sizeof(derived_template) / sizeof(*derived_template),
      &key_handle
    };

    if (output_bitlen > mac_size) {
      // Two allocations:
      kdf_params->ulAdditionalDerivedKeys = 1;
      kdf_params->pAdditionalDerivedKeys = &derived_key;
    }

    /* Build our SECItem with our passed parameters. */
    ASSERT_NE(kdf_params, nullptr);
    SECItem params_item = { siBuffer, (unsigned char *)kdf_params, sizeof(*kdf_params) };

    /* Validate that our output is an even number of bytes. */
    ASSERT_EQ((output_bitlen % 8), 0u);

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_Derive(p11_key.get(), kdf_mech, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8));
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

    /* Since RunKDF tests the ability to derive secret keys, test the ability
     * to derive additional parameters. */
    CK_ATTRIBUTE key_template[1];
    CK_OBJECT_CLASS data = CKO_DATA;
    key_template[0] = { CKA_CLASS, &data, sizeof(data) };

    /* Choose CKM_SHA512_HMAC because it is long enough to hold all CAVP
     * key sizes. */
    ScopedPK11SymKey result(PK11_DeriveWithTemplate(p11_key.get(), CKM_NSS_SP800_108_FEEDBACK_KDF_DERIVE_DATA, &params_item, CKM_SHA512_HMAC, CKA_SIGN, output_bitlen/8, key_template, 1, PR_FALSE));
    ASSERT_NE(result, nullptr);

    ASSERT_EQ(PK11_ExtractKeyValue(result.get()), SECSuccess);

    /* We don't need to free this -- it is just a reference... */
    SECItem *actual_item = PK11_GetKeyData(result.get());
    ASSERT_NE(actual_item, nullptr);

    /* Wrap our expected output in a SECItem for easy comparisons. */
    SECItem expected_item = {siBuffer, expected, output_bitlen/8};
    ASSERT_EQ(SECITEM_CompareItem(actual_item, &expected_item), 0);
  }

  /* == Helpers to run Counter mode CAVP tests == */

  void RunCounterBeforeFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
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

    RunKDF(CKM_NSS_SP800_108_COUNTER_KDF_DERIVE_DATA, prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunCounterMiddleFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *before_fixed_input, uint32_t before_fixed_input_len, uint8_t *after_fixed_input, uint32_t after_fixed_input_len, uint8_t *expected) {
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

    RunKDF(CKM_NSS_SP800_108_COUNTER_KDF_DERIVE_DATA, prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunCounterAfterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
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

    RunKDF(CKM_NSS_SP800_108_COUNTER_KDF_DERIVE_DATA, prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  /* == Helpers to run Feedback mode CAVP tests == */

  void RunFeedbackNoCounterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *iv, uint32_t iv_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
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

  /* == Helpers to run Pipeline mode CAVP tests == */

  void RunPipelineNoCounterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
    CK_PRF_DATA_PARAM dataParams[] = {
      { CK_SP800_108_ITERATION_VARIABLE, NULL, 0 },
      { CK_SP800_108_BYTE_ARRAY, fixed_input, fixed_input_len }
    };

    CK_SP800_108_KDF_PARAMS kdf_params = {
      prf_mech,
      2,
      dataParams,
      0,
      NULL
    };

    RunKDF(CKM_NSS_SP800_108_DOUBLE_PIPELINE_KDF_DERIVE_DATA, prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunPipelineCounterBeforeIterTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
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

    RunKDF(CKM_NSS_SP800_108_DOUBLE_PIPELINE_KDF_DERIVE_DATA, prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunPipelineCounterAfterIterTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
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

    RunKDF(CKM_NSS_SP800_108_DOUBLE_PIPELINE_KDF_DERIVE_DATA, prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
  }

  void RunPipelineCounterAfterFixedTest(CK_MECHANISM_TYPE prf_mech, uint32_t counter_bitlen, uint32_t output_bitlen, uint8_t *key, uint32_t key_len, uint8_t *fixed_input, uint32_t fixed_input_len, uint8_t *expected) {
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

    RunKDF(CKM_NSS_SP800_108_DOUBLE_PIPELINE_KDF_DERIVE_DATA, prf_mech, &kdf_params, output_bitlen, key, key_len, expected);
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

TEST_F(Pkcs11KbkdfTest, TestNISTCAVPPipelineNoCounterFixed) {
  for (size_t offset = 0; offset < PK11_KBKDFPipelineNoCounterFixed_Len; offset++) {
    PipelineNoCounterFixed test = PK11_KBKDFPipelineNoCounterFixed[offset];
    RunPipelineNoCounterFixedTest(test.prf_mech, test.output_bitlen, test.key, test.key_len, test.fixed_input, test.fixed_input_len, test.expected);
  }
}

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
