/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "kbkdf.h"

struct KBKDFContextStr {
    /* Pseudo-random function we're using for this KDF. */
    KBKDFPrf prf;

    /* Mode of the KDF to use; there's three:
     *  - Counter, with an increasing counter each time the PRF is called,
     *  - Feedback, where the output from the previous PRF call is fed
     *              into the next,
     *  - Double Pipeline, where the PRF is called twice for each block, once
     *                     on just the fixed input data (to generate a secret
     *                     value A_i) and once on both the fixed input data
     *                     and the secret value A_i.
     */
    KBKDFMode mode;
    unsigned int output_bitlen;
    unsigned int counter_bitlen;
};

SECStatus KBKDF_Init(KBKDFContext *ctx, KBKDF_PRF prf, KBKDFMode mode,
                     unsigned int output_bitlen, unsigned int counter_bitlen) {

}

KBKDFContext *KBKDF_Create(KBKDF_PRF prf, KBKDFMode mode,
                           unsigned int output_bitlen,
                           unsigned int counter_bitlen) {
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

}
