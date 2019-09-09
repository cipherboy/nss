/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "kbkdf.h"
#include "blapi.h"
#include "blapit.h"

struct KBKDFContextStr {
    /* Pseudo-random function we're using for this KDF. */
    KBKDFPrf prfType;
    union {
        CMACContext cmac;
        HMACContext hmac;
    } prf;

    /* Mode of the KDF to use; there are three:
     *
     *  - Counter, with an increasing counter each time the PRF is called,
     *  - Feedback, where the output from the previous PRF call is fed
     *              into the next,
     *  - Double Pipeline, where the PRF is called twice for each block, once
     *                     on just the fixed input data (to generate a secret
     *                     value A_i) and once on both the fixed input data
     *                     and the secret value A_i.
     */
    KBKDFMode chainingType;

    /* Size (in bytes) of the amount of output to take from each PRF call.
     *
     * Note: this differs from the input to KBKDF_{Init,Create} because it
     * holds bytes and not bits. */
    unsigned int output_len;

    /* Size (in bytes) for the increasing counter.
     *
     * Note: this differs from the input to KBKDF_{Init,Create} because it
     * holds bytes and not bits. */
    unsigned int counter_len;
};

SECStatus KBKDF_Init(KBKDFContext *ctx, KBKDF_PRF prf, KBKDFMode mode,
                     unsigned int output_bitlen, unsigned int counter_bitlen) {
    if (ctx == NULL) {
        return SECFailure;
    }

    ctx->prfType = prf;
    ctx->chainingType = mode;

    /* Handle detection of output_bitlen based on underlying PRF. */
    if (output_bitlen == 0) {
        switch (prf) {
            case KBKDF_CMAC_AES_128:
            case KBKDF_CMAC_AES_192:
            case KBKDF_CMAC_AES_256:
                output_bitlen = AES_BLOCK_SIZE;
                break;
            case KBKDF_HMAC_SHA1:
                output_bitlen = SHA1_LENGTH;
                break;
            case KBKDF_HMAC_SHA2_256:
                output_bitlen = SHA256_LENGTH;
                break;
            case KBKDF_HMAC_SHA2_384:
                output_bitlen = SHA384_LENGTH;
                break;
            case KBKDF_HMAC_SHA2_512:
                output_bitlen = SHA512_LENGTH;
                break;
            default:
                /* We expected a known constant. If someone hits this assert,
                 * the caller has passed an invalid KBKDF_PRF constant. This
                 * might happen during development when a new KBKDF_PRF
                 * constant is added but is not yet finished. */
                PORT_Assert(0);
                PORT_SetError(SEC_ERROR_INVALID_ARGS);
                return SECFailure;
        }
    }

    /* Validate assumptions we gave in kbkdf.h. */
    if ((output_bitlen % 8) != 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    ctx->output_bitlen;

    /* Validate assumptions we gave in kbkdf.h. */
    if (counter_bitlen == 0 || counter_bitlen > 64 || (counter_bitlen % 8) != 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    ctx->counter_bitlen = counter_bitlen / 8;

    /* Since the key the PRF is initialized with depends on values passed to
     * KBKDF_Derive, we don't initialize it here. This gives us the benefit of
     * not needing to free it in KBKDF_Destroy either. */

    return SECSuccess;
}

KBKDFContext *KBKDF_Create(KBKDF_PRF prf, KBKDFMode mode,
                           unsigned int output_bitlen,
                           unsigned int counter_bitlen) {
    KBKDFContext *result = PORT_New(KBKDFContext);
    if (KBKDF_Init(result, prf, mode, output_bitlen, counter_bitlen) !=
            SECSuccess) {
        KBKDF_Destroy(result, PR_TRUE);
        return NULL;
    }

    return result;
}

SECStatus KBKDF_Derive(KBKDFContext *ctx, const unsigned char *key,
                       unsigned int key_len,
                       const unsigned char *label,
                       unsigned int label_len,
                       const unsigned char *context,
                       unsigned int context_len,
                       const unsigned char *iv,
                       unsigned int iv_len,
                       const unsigned char *result,
                       unsigned int result) {

}

void KBKDF_Destroy(KBKDFContext *ctx, PRBool free_it) {
    if (ctx == NULL) {
        return;
    }

    /* Assumption: the PRF gets initialized and destroyed at each call to
     * KBKDF_Derive. While this *can* create a little bit of churn, it is
     * necessary because the key of the PRF might change each call to Derive.
     * Thus we don't need to free it here. */

    PORT_Memset(ctx, 0, sizeof(*ctx));

    if (free_it == PR_TRUE) {
        PORT_Free(ctx);
    }
}
