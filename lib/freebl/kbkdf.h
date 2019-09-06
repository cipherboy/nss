/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _KBKDF_H_
#define _KBKDF_H_

typedef struct KBKDFContextStr KBKDFContext;

SEC_BEGIN_PROTOS

/* Enum for identifying the underlying block cipher we're using internally. */
typedef enum {
    KBKDF_CMAC_AES_128 = 0,
    KBKDF_CMAC_AES_192 = 1,
    KBKDF_CMAC_AES_256 = 2,
    KBKDF_HMAC_SHA1 = 3,
    KBKDF_HMAC_SHA2_256 = 4,
    KBKDF_HMAC_SHA2_384 = 5,
    KBKDF_HMAC_SHA2_512 = 6
} KBKDFPrf;

typedef enum {
    KBKDF_COUNTER = 0,
    KBKDF_FEEDBACK = 1,
    KBKDF_DOUBLE_PIPELINE = 2
} KBKDFMode;

/* Initialize an existing KBKDFContext struct. This takes four parameters:
 *  - prf, the underlying pseudo-random function to use,
 *  - mode, the chaining mode to use,
 *  - output_bitlen, the number of bits in the output size,
 *  - counter_bitlen, the number of bits to use for the internal counter.
 */
SECStatus KBKDF_Init(KBKDFContext *ctx, KBKDF_PRF prf, KBKDFMode mode,
                     unsigned int output_bitlen, unsigned int counter_bitlen);

/* Create and initialize a new KBKDF context with the specified parameters.
 * See KBKDF_Init for more information about the parameters. */
KBKDFContext *KBKDF_Create(KBKDF_PRF prf, KBKDFMode mode,
                           unsigned int output_bitlen,
                           unsigned int counter_bitlen);

/* Derive a key (placing the output K0 in result) using the specified
 * parameters:
 *  - key (K1), the key to derive with,
 *  - key_len, the length of key, in bytes,
 *  - label (Label), the purpose of the derived material,
 *  - label_len, the length of label, in bytes,
 *  - context (Context), the context of the derived material (e.g., entities),
 *  - context_len, the length of context, in bytes,
 *  - iv (IV), the initialization vector for KBKDF_FEEDBACK, NULL otherwise,
 *  - iv_len, the length of iv (zero if not using KBKDF_FEEDBACK),
 *  - result (K0), an allocated buffer to place the resulting key material in,
 *  - result_len (L), the length of result, in bytes.
 */
SECStatus KBKDF_Derive(KBKDFContext *ctx, const unsigned char *key,
                       unsigned int key_len,
                       const unsigned char *label,
                       unsigned int label_len,
                       const unsigned char *context,
                       unsigned int context_len,
                       const unsigned char *iv,
                       unsigned int iv_len,
                       const unsigned char *result,
                       unsigned int result);

/* Destroy a KBKDF Context, optionally freeing it. */
void KBKDF_Destroy(KBKDFContext *ctx, PRBool free_it);

SEC_END_PROTOS

#endif
