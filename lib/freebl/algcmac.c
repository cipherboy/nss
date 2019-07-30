/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "secport.h"
#include "blapit.h"
#include "blapii.h"
#include "blapi.h"
#include "algcmac.h"
#include "secerr.h"
#include "nspr.h"

#include "stdio.h"

struct CMACContextStr {
    /* Information about the block cipher to use internally. The cipher should
     * be placed in ECB mode so that we can use it to directly encrypt blocks.
     * Store a pointer to the cipher's context and keep track of the block
     * size so we can validate input and return parameters ourselves.
     *
     * To add a new cipher, add an entry to CMACCiphers, update CMAC_Init,
     * cmac_Encrypt, and CMAC_Destroy methods to handle the new cipher, and
     * add a new Context pointer to the cipher union with the correct type. */
    CMACCiphers cipherType;
    union {
        void *raw;
        AESContext *aes;
    } cipher;
    int blockSize;

    /* Whether or not we allocated (via CMAC_Create) this CMACContext. This
     * affects CMAC_Destroy. */
    PRBool wasAllocated;

    /* Internal keys which are conditionally used by the algorithm. Derived
     * from encrypting the NULL block. We leave the storing of (and the
     * cleanup of) the CMAC key to the underlying block cipher. */
    unsigned char *k1;
    unsigned char *k2;

    /* When Update is called with data which isn't a multiple of the block
     * size, we need a place to put it. HMAC handles this by passing it to
     * the underlying hash function right away; we can't do that as the
     * contract on the cipher object is different. */
    unsigned int partialIndex;
    unsigned char *partialBlock;

    /* Last encrypted block. This gets xor-ed with partialBlock prior to
     * encrypting it. NIST defines this to be the empty string to begin. */
    unsigned char *lastBlock;
};

/* byte arrays are really the wrong level for this: we want to shift the
 * entire block left by one bit. With AES, this ends up being a 128-bit
 * block size that we have to deal with manually; a union data structure
 * between a __uint128_t and a byte array would be better. */
static unsigned char *left_shift(unsigned char *data, int length) {
    unsigned char *result = PORT_ZNewArray(unsigned char, length);

    for (int i = 0; i < length; i++) {
        result[i] = data[i] << 1;
        if (i + 1 < length) {
            result[i] |= data[i+1] >> 7;
        }
    }

    return result;
}

static SECStatus cmac_Encrypt(CMACContext *ctx, unsigned char *output,
                              unsigned int *outputLen,
                              unsigned int maxOutputLen,
                              const unsigned char *input,
                              unsigned int inputLen) {
    if (ctx->cipherType == CMAC_AES) {
        unsigned int tmpOutputLen;
        SECStatus ret = AES_Encrypt(ctx->cipher.aes, output, &tmpOutputLen, maxOutputLen, input, inputLen);

        if (outputLen != NULL) {
            *outputLen = tmpOutputLen;
        }

        return ret;
    }

    return SECFailure;
}

/* NIST SP.800-38B, 6.1 Subkey Generation */
static SECStatus cmac_GenerateSubkeys(CMACContext *ctx) {
    unsigned char null_block[MAX_BLOCK_SIZE];
    unsigned char L[MAX_BLOCK_SIZE];
    PORT_Memset(null_block, 0, MAX_BLOCK_SIZE);

    /* Step 1: L = AES(key, null_block) */
    if (cmac_Encrypt(ctx, L, NULL, ctx->blockSize, null_block, ctx->blockSize) != SECSuccess) {
        ctx->k1 = NULL;
        ctx->k2 = NULL;
        return SECFailure;
    }

    /* In the following, some effort has been made to pretend to be constant
     * time. However, the compiler will likely optimize away the first branch's
     * XOR operation. While leaking two bits of key information likely won't
     * affect the security of this algorithm, it is something to be aware of. */

    /* Step 2: If MSB(L) = 0, K1 = L << 1. Else, K1 = (L << 1) ^ R_b. */
    if ((L[0] & 0x80) == 0) {
        ctx->k1 = left_shift(L, ctx->blockSize);
        ctx->k1[ctx->blockSize-1] ^= 0x00;
    } else {
        /* For a 128-bit block cipher, R_b is 0b10000111 == 135 == 0x87. This
         * will need to be modified if a 64-bit block cipher is ever used. */
        ctx->k1 = left_shift(L, ctx->blockSize);
        ctx->k1[ctx->blockSize-1] ^= 0x87;
    }

    /* Step 3: If MSB(K1) = 0, K2 = K1 << 1. Else, K2 = (K1 <, 1) ^ R_b. */
    if ((ctx->k1[0] & 0x80) == 0) {
        ctx->k2 = left_shift(ctx->k1, ctx->blockSize);
        ctx->k2[ctx->blockSize-1] ^= 0x00;
    } else {
        /* For a 128-bit block cipher, R_b is 0b10000111 == 135 == 0x87. This
         * will need to be modified if a 64-bit block cipher is ever used. */
        ctx->k2 = left_shift(ctx->k1, ctx->blockSize);
        ctx->k2[ctx->blockSize-1] ^= 0x87;
    }

    /* Any intermediate value in the computation of the subkey shall be
     * secret. */
    PORT_Memset(null_block, 0, MAX_BLOCK_SIZE);
    PORT_Memset(L, 0, MAX_BLOCK_SIZE);

    /* Step 4: Return the values. */
    return SECSuccess;
}

/* NIST SP.800-38B, 6.2 MAC Generation step 6 */
static SECStatus cmac_UpdateState(CMACContext *ctx) {
    if (ctx == NULL || ctx->partialIndex != ctx->blockSize) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    /* Step 6: C_i = CIPHER(key, C_{i-1} ^ M_i)  for 1 <= i <= n, and
     *         C_0 is defined as the empty string. */

    for (unsigned int index = 0; index < ctx->blockSize; index++) {
        ctx->partialBlock[index] ^= ctx->lastBlock[index];
    }

    return cmac_Encrypt(ctx, ctx->lastBlock, NULL, ctx->blockSize,
                        ctx->partialBlock, ctx->blockSize);
}

SECStatus CMAC_Init(CMACContext *ctx, CMACCiphers type,
                    const unsigned char *key, unsigned int key_len) {
    if (ctx == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    PORT_Memset(ctx, 0, sizeof(*ctx));

    if (type != CMAC_AES) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    ctx->blockSize = AES_BLOCK_SIZE;
    ctx->cipherType = CMAC_AES;
    ctx->cipher.aes = AES_CreateContext(key, NULL, NSS_AES, 1, key_len, ctx->blockSize);
    if (ctx->cipher.aes == NULL) {
        return SECFailure;
    }

    ctx->wasAllocated = PR_FALSE;
    return CMAC_Begin(ctx);
}

CMACContext *CMAC_Create(CMACCiphers type, const unsigned char *key,
                         unsigned int key_len) {
    CMACContext *result = PORT_ZNew(CMACContext);

    if (CMAC_Init(result, type, key, key_len) != SECSuccess) {
        /* CMAC_Init intentionally clobbers the contents of ctx, but for
         * PORT_ZFree to be called, we need to set ctx->wasAllocated to
         * PR_TRUE. */
        result->wasAllocated = PR_TRUE;
        CMAC_Destroy(result, PR_TRUE);
        return NULL;
    }

    result->wasAllocated = PR_TRUE;
    return result;
}

SECStatus CMAC_Begin(CMACContext *ctx) {
    if (ctx == NULL) {
        return SECFailure;
    }

    PORT_ZFree(ctx->k1, ctx->blockSize);
    PORT_ZFree(ctx->k2, ctx->blockSize);
    PORT_ZFree(ctx->partialBlock, ctx->blockSize);
    PORT_ZFree(ctx->lastBlock, ctx->blockSize);

    if (cmac_GenerateSubkeys(ctx) != SECSuccess) {
        return SECFailure;
    }

    ctx->partialIndex = 0;
    ctx->partialBlock = PORT_ZNewArray(unsigned char, ctx->blockSize);

    /* Step 5: Let C_0 = 0^b. */
    ctx->lastBlock = PORT_ZNewArray(unsigned char, ctx->blockSize);

    return SECSuccess;
}

/* NIST SP.800-38B, 6.2 MAC Generation */
SECStatus CMAC_Update(CMACContext *ctx, const unsigned char *data,
                 unsigned int data_len) {
    int data_index = 0;
    if (ctx == NULL || ctx->cipher.raw == NULL || ctx->k1 == NULL ||
            ctx->k2 == NULL) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (data == NULL || data_len == 0) {
        return SECSuccess;
    }

    /* Copy as many bytes from data into ctx->partialBlock as we can, up to
     * the maximum of the remaining data and the remaining space in
     * ctx->partialBlock.
     *
     * Note that we swap the order (encrypt *then* copy) because the last
     * block is different from the rest. If we end on an even multiple of
     * the block size, we have to be able to XOR it with K1. But we won't know
     * that it is the last until CMAC_Finish is called (and by then, CMAC_Update
     * has already returned). */
    while (data_index < data_len) {
        if (ctx->partialIndex == ctx->blockSize) {
            if (cmac_UpdateState(ctx) != SECSuccess) {
                return SECFailure;
            }

            ctx->partialIndex = 0;
        }

        unsigned int copy_len = data_len - data_index;
        if (copy_len > (ctx->blockSize - ctx->partialIndex)) {
            copy_len = ctx->blockSize - ctx->partialIndex;
        }

        PORT_Memcpy(ctx->partialBlock + ctx->partialIndex, data + data_index, copy_len);
        data_index += copy_len;
        ctx->partialIndex += copy_len;
    }

    return SECSuccess;
}

/* NIST SP.800-38B, 6.2 MAC Generation */
SECStatus CMAC_Finish(CMACContext *ctx, unsigned char *result,
                      unsigned int *result_len,
                      unsigned int max_result_len) {
    if (ctx == NULL || result == NULL || max_result_len == 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (max_result_len > ctx->blockSize) {
        /* This is a weird situation. The PKCS #11 soft tokencode passes
         * sizeof(result) here, which is hard-coded as SFTK_MAX_MAC_LENGTH.
         * This later gets truncated to min(SFTK_MAX_MAC_LENGTH, requested). */
        max_result_len = ctx->blockSize;
    }

    /* Step 4: If M_n* is a complete block, M_n = K1 ^ M_n*. Else,
     * M_n = K2 ^ (M_n* || 10^j). */
    if (ctx->partialIndex == ctx->blockSize) {
        /* XOR in K1. */
        for (unsigned int index = 0; index < ctx->blockSize; index++) {
            ctx->partialBlock[index] ^= ctx->k1[index];
        }

        /* Encrypt the block. */
        if (cmac_UpdateState(ctx) != SECSuccess) {
            return SECFailure;
        }
    } else {
        /* Use 10* padding on the partial block. */
        ctx->partialBlock[ctx->partialIndex++] = 0x80;
        PORT_Memset(ctx->partialBlock + ctx->partialIndex, 0,
                    ctx->blockSize - ctx->partialIndex);
        ctx->partialIndex = ctx->blockSize;

        /* XOR in K2. */
        for (unsigned int index = 0; index < ctx->blockSize; index++) {
            ctx->partialBlock[index] ^= ctx->k2[index];
        }

        /* Encrypt the block. */
        if (cmac_UpdateState(ctx) != SECSuccess) {
            return SECFailure;
        }
    }

    /* Step 7 & 8: T = MSB_tlen(C_n); return T. */
    PORT_Memcpy(result, ctx->lastBlock, max_result_len);
    if (result_len != NULL) {
        *result_len = max_result_len;
    }
    return SECSuccess;
}

void CMAC_Destroy(CMACContext *ctx, PRBool free_it) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->cipher.raw != NULL) {
        if (ctx->cipherType == CMAC_AES) {
            AES_DestroyContext(ctx->cipher.aes, PR_TRUE);
        }
    }

    PORT_ZFree(ctx->k1, ctx->blockSize);
    PORT_ZFree(ctx->k2, ctx->blockSize);
    PORT_ZFree(ctx->partialBlock, ctx->blockSize);
    PORT_ZFree(ctx->lastBlock, ctx->blockSize);

    if (ctx->wasAllocated && free_it == PR_TRUE) {
        PORT_ZFree(ctx, sizeof(*ctx));
    }

    /* When ctx wasn't allocated by create, we don't memset the contents: it
     * only contains pointers to data (freed by PORT_ZFree above) and doesn't
     * directly contain sensitive data. We assume the AES_DestroyContext(...)
     * call handles sanitizing the contents of ctx->cipher as this context
     * only stores a pointer and not the full cipher struct. */
}
