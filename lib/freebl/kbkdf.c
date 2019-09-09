/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "blapi.h"
#include "kbkdf.h"

#include "alghmac.h"
#include "cmac.h"
#include "secerr.h"

typedef union {
    CMACContext *cmac;
     HMACContext *hmac;
} kbkdf_PRFType;

struct KBKDFContextStr {
    /* Pseudo-random function we're using for this KDF. */
    KBKDFPrf prfType;

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

SECStatus KBKDF_Init(KBKDFContext *ctx, KBKDFPrf prf, KBKDFMode mode,
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
                 * the caller has passed an invalid KBKDFPrf constant. This
                 * might happen during development when a new KBKDFPrf
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
    ctx->output_len = output_bitlen / 8;

    /* Validate assumptions we gave in kbkdf.h. */
    if (counter_bitlen == 0 || counter_bitlen > 64 || (counter_bitlen % 8) != 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    ctx->counter_len = counter_bitlen / 8;

    return SECSuccess;
}

KBKDFContext *KBKDF_Create(KBKDFPrf prf, KBKDFMode mode,
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
                       unsigned int result_len) {
    return SECFailure;
}

void KBKDF_Destroy(KBKDFContext *ctx, PRBool free_it) {
    if (ctx == NULL) {
        return;
    }

    PORT_Memset(ctx, 0, sizeof(*ctx));

    if (free_it == PR_TRUE) {
        PORT_Free(ctx);
    }
}
