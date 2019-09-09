/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "blapi.h"
#include "kbkdf.h"

#include "alghmac.h"
#include "cmac.h"
#include "secerr.h"

/* Internal type: pointers to various contexts. These get created and
 * destroyed as part of KBKDF_Derive. */
typedef union {
    CMACContext *cmac;
    HMACContext *hmac;
} kbkdf_PRFType;

/*
 * Design notes: KBKDF implements the NIST 800-108 publication. We take the
 * view that an application will likely have only a few KDF types (where the
 * type is specified by the PRF, the chaining mode, and output/counter
 * lengths), but have potentially many invocations of it. In particular, we
 * let the application delay specifying the key until they call
 * KBKDF_Derive(...). This lets them have a single instance of a KBKDFContext
 * and reuse it throughout all call sites.
 */

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

    /* Handle detection of output_bitlen based on underlying PRF. This lets
     * the caller ignore the details about the size of their PRF and use the
     * entire output. */
    if (output_bitlen == 0) {
        switch (prf) {
            case KBKDF_CMAC_AES_128:
            case KBKDF_CMAC_AES_192:
            case KBKDF_CMAC_AES_256:
                output_bitlen = AES_BLOCK_SIZE * 8;
                break;
            case KBKDF_HMAC_SHA1:
                output_bitlen = SHA1_LENGTH * 8;
                break;
            case KBKDF_HMAC_SHA2_256:
                output_bitlen = SHA256_LENGTH * 8;
                break;
            case KBKDF_HMAC_SHA2_384:
                output_bitlen = SHA384_LENGTH * 8;
                break;
            case KBKDF_HMAC_SHA2_512:
                output_bitlen = SHA512_LENGTH * 8;
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
    if (counter_bitlen > 64 || (counter_bitlen % 8) != 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    /* counter_bitlen cannot be zero if we're in counter mode: we need at
     * least one bit to count with! */
    if (ctx->prfType == KBKDF_COUNTER && coutner_bitlen == 0) {
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

SECStatus kbkdf_ValidateNumIters(KBKDFContext *ctx, unsigned int num_iters) {
    if (ctx->chainingType == KBKDF_COUNTER ||
            (ctx->chainingType == KBKDF_FEEDBACK && ctx->counter_len > 0)) {
        /* We validate that the size of num_iters is fine for our counter.
         * Interestingly, NIST 800-108 doesn't specify whether this check is
         * necessary for the Feedback mode with optional counter; since they
         * don't explicitly specify that the counter can wrap, we take the
         * view that its invalid to request more iterations than what the
         * counter provides. */
        if (num_iters >= (1 << (8 * ctx->counter_len))) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return SECFailure;
        }

        /* Don't return as we want the non-zero check. */
    }

    /* Technically we're supposed to validate that num_iters <= (2^32) - 1.
     * Since we're using an unsigned int for both result_len and
     * ctx->output_len, this is guaranteed for us. However, we do validate
     * that we have at least one iteration, otherwise our PRF wouldn't output
     * anything. */
    if (num_iters == 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    return SECSuccess;
}

SECStatus KBKDF_Derive(KBKDFContext *ctx, const unsigned char *key,
                       unsigned int key_len,
                       const unsigned char *label,
                       unsigned int label_len,
                       const unsigned char *context,
                       unsigned int context_len,
                       const unsigned char *iv,
                       unsigned int iv_len,
                       unsigned char *result,
                       unsigned int result_len) {
    if (ctx == NULL || key == NULL || label == NULL || context == NULL) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    /* Feedback chaining mode is the only place where IV is used; otherwise,
     * we ignore its value. */
    if (ctx->chainingType == KBKDF_FEEDBACK && iv == NULL) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    kbkdf_PRFType prf_ctx = NULL;
    unsigned int num_iters = (result_len + (ctx->output_len - 1)) / ctx->output_len;
    SECStatus result = SECFailure;

    if (kbkdf_ValidateNumIters(ctx, num_iters) != SECSuccess) {
        return SECFailure;
    }

    for (int i = 1; i <= num_iters; i++) {
        unsigned int offset = (i - 1) * ctx->output_len;
        unsigned char *result_offset = result + offset;
        result = // SOMETHING
    }

    return result;
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
