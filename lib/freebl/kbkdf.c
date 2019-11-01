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

    /* Endianness */
    KBKDFByteOrder endianness;

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

SECStatus
KBKDF_Init(KBKDFContext *ctx, KBKDFPrf prf, KBKDFMode mode,
           unsigned int output_bitlen, unsigned int counter_bitlen)
{
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
    if (ctx->chainingType == KBKDF_COUNTER && counter_bitlen == 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }
    ctx->counter_len = counter_bitlen / 8;

    return SECSuccess;
}

KBKDFContext *
KBKDF_Create(KBKDFPrf prf, KBKDFMode mode,
             unsigned int output_bitlen,
             unsigned int counter_bitlen)
{
    KBKDFContext *result = PORT_New(KBKDFContext);
    if (KBKDF_Init(result, prf, mode, output_bitlen, counter_bitlen) !=
        SECSuccess) {
        KBKDF_Destroy(result, PR_TRUE);
        return NULL;
    }

    return result;
}

SECStatus
kbkdf_ValidateNumIters(KBKDFContext *ctx, unsigned int num_iters)
{
    if (ctx->chainingType == KBKDF_COUNTER) {
        /* We validate that the size of num_iters is fine for our counter. */
        if (num_iters >= (1 << (8 * ctx->counter_len))) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return SECFailure;
        }

        /* Don't return as we want the non-zero check. */
    }

    /* Technically we're supposed to validate that num_iters <= (2^32) - 1
     * for Feedback and Double-Pipeline chaining modes. Since we're using an
     * unsigned int for result_len, ctx->output_len, and num_iters, this is
     * guaranteed for us. However, we do validate that we have at least one
     * iteration, otherwise our PRF wouldn't output anything. */
    if (num_iters == 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    return SECSuccess;
}

void
kbkdf_WriteResultLength(KBKDFContext *ctx, unsigned char *result,
                        unsigned long long int result_len,
                        unsigned int result_bit_len)
{
    unsigned long long int result_len_in_bits = result_len * 8;
    if (ctx->endiannes == KBKDF_BigEndian) {
        switch (result_bit_len) {
            case 8:
                *result = (unsigned char)(result_len & 0xFF);
                break;
            case 16:
                break;
            case 24:
                break;
            case 32:
                break;
            case 40:
                break;
            case 48:
                break;
            case 56:
                break;
            case 64:
                break;
        }
    } else {
        switch (result_bit_len) {
            case 8:
                *result = (unsigned char)(result_len & 0xFF);
                break;
            case 16:
                break;
            case 24:
                break;
            case 32:
                break;
            case 40:
                break;
            case 48:
                break;
            case 56:
                break;
            case 64:
                break;
        }
    }
}

SECStatus
kbkdf_ConstructRoundData(KBKDFContext *ctx,
                         const unsigned char *iv,
                         unsigned int iv_len,
                         const unsigned char *label,
                         unsigned int label_len,
                         unsigned int separator_len,
                         const unsigned char *context,
                         unsigned int context_len,
                         unsigned long long int result_len,
                         unsigned int result_bit_len,
                         unsigned char **round_data,
                         unsigned int *round_data_len)
{
    switch (ctx->chainingType) {
        case KBKDF_COUNTER:
            /* Counter chaining mode has no data passed from round to round
             * besides the incrementing counter. */
            *round_data_len = 0;
            *round_data = NULL;
            break;
        case KBKDF_FEEDBACK:
            /* Feedback chaining mode takes the iv parameter and reuses that.
             * Since we assume that we can free round_data inside our loop, we
             * copy iv into round_data. */
            *round_data_len = iv_len;
            *round_data = (unsigned char *)PORT_ZAlloc(*round_data_len);
            if (*round_data == NULL) {
                PORT_SetError(SEC_ERROR_NO_MEMORY);
                return SECFailure;
            }

            PORT_Memcpy(*round_data, iv, *round_data_len);
            break;
        case KBKDF_DOUBLE_PIPELINE:
            unsigned char *round_offset;

            *round_data_len = label_len + separator_len + context_len + (result_bit_len / 8);
            if (round_data_len < label_len || round_data_len < separator_len ||
                round_data_len < context_len || round_data_len < (result_bit_len / 8)) {
                /* We had an arithmetic overflow because our arguments are
                 * too large. Refuse to continue. */
                PORT_SetError(SEC_ERROR_NO_MEMORY);
                return SECFailure;
            }

            *round_data = (unsigned char *)PORT_ZAlloc(*round_data_len);
            if (*round_data == NULL) {
                PORT_SetError(SEC_ERROR_NO_MEMORY);
                return SECFailure;
            }
            round_offset = *round_data;

            PORT_Memcpy(round_offset, label, label_len);
            round_offset += label_len;

            /* Since we used PORT_ZAlloc, *round_data has been initialized to
             * all zeros; this means we can simply skip the separator length
             * without explicitly zeroing it. */
            round_offset += separator_len;

            PORT_Memcpy(round_offset, context, context_len);
            round_offset += context_len;

            kbkdf_WriteResultLength(ctx, round_offset, result_len, result_bit_len);
            break;
        default:
            /* If you hit this assert, you're either trying to define a new
             * KDF chaining mode or you were passed invalid data. */
            PORT_Assert(0);
            return SECFailure;
    }

    return SECSuccess;
}

SECStatus
KBKDF_Derive(KBKDFContext *ctx,
             const unsigned char *key,
             unsigned int key_len,
             const unsigned char *label,
             unsigned int label_len,
             unsigned int separator_len,
             const unsigned char *context,
             unsigned int context_len,
             const unsigned char *iv,
             unsigned int iv_len,
             unsigned char *result,
             unsigned long long int result_len,
             unsigned int result_bit_len)
{
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

    /* We assume result_bit_len is a multiple of 8, is bounded below by 0,
     * and is bounded above by 64. */
    if (result_bit_len == 0 || result_bit_len > 64 ||
        (result_bit_len % 8) != 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    /* When result_bit_len isn't 64, validate that it is large enough to hold
     * result_len. Otherwise, since result_len is 64 bits, 64 bits is clearly
     * enough to hold result_len. */
    if (result_bit_len < 64 &&
        (1ULL << ((unsigned long long int)result_bit_len)) <= result_len) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    kbkdf_PRFType prf_ctx;
    unsigned long long int cur_iter;
    unsigned int num_iters = (result_len + (ctx->output_len - 1)) / ctx->output_len;
    unsigned char *round_data;
    unsigned int round_data_len;

    if (kbkdf_ValidateNumIters(ctx, num_iters) != SECSuccess) {
        return SECFailure;
    }

    if (kbkdf_ConstructRoundData(ctx, iv, iv_len, label, label_len,
                                 separator_len, context, context_len,
                                 result_len, result_bit_len, &round_data,
                                 &round_data_len) != SECSuccess) {
        return SECFailure;
    }

    for (cur_iter = 1; cur_iter <= num_iters; cur_iter++) {
        unsigned int offset = (cur_iter - 1) * ctx->output_len;
        unsigned char *result_offset = result + offset;
    }

    PORT_ZFree(round_data, round_data_len);

    return SECSuccess;
}

void
KBKDF_Destroy(KBKDFContext *ctx, PRBool free_it)
{
    if (ctx == NULL) {
        return;
    }

    /* We store no sensitive information in our context so we don't need to
     * zero it. */

    if (free_it == PR_TRUE) {
        PORT_Free(ctx);
    }
}
