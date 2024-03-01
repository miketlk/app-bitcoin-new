/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#ifndef SKIP_FOR_CMOCKA
#include "os.h"
#include "cx.h"
#include "cx_stubs.h"
#include "cx_ecfp.h"
#include "ox_ec.h"
#endif

#include "common/base58.h"
#include "common/bip32.h"
#include "common/format.h"
#include "common/read.h"
#include "common/write.h"

#include "crypto.h"

#ifndef SKIP_FOR_CMOCKA
#include "cx_ram.h"
#include "lcx_ripemd160.h"
#include "cx_ripemd160.h"
#include "../../cxram_stash.h"
#endif

#include "util.h"

#ifndef SKIP_FOR_CMOCKA

/**
 * Generator for secp256k1, value 'g' defined in "Standards for Efficient Cryptography"
 * (SEC2) 2.7.1.
 */
// clang-format off
const uint8_t secp256k1_generator[] = {
    0x04,
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
// clang-format on

/**
 * Modulo for secp256k1
 */
const uint8_t secp256k1_p[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f};

/**
 * Curve order for secp256k1
 */
const uint8_t secp256k1_n[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

/**
 * (p + 1)/4, used to calculate square roots in secp256k1
 */
const uint8_t secp256k1_sqr_exponent[] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c};

/* BIP0341 tags for computing the tagged hashes when tweaking public keys */
static const uint8_t BIP0341_taptweak_tag[] = {'T', 'a', 'p', 'T', 'w', 'e', 'a', 'k'};

static int secp256k1_point(const uint8_t scalar[static 32], uint8_t out[static 65]);

/**
 * Gets the point on the SECP256K1 that corresponds to kG, where G is the curve's generator point.
 * Returns -1 if point is Infinity or any error occurs; 0 otherwise.
 */
static int secp256k1_point(const uint8_t k[static 32], uint8_t out[static 65]) {
    memcpy(out, secp256k1_generator, 65);
    if (CX_OK != cx_ecfp_scalar_mult_no_throw(CX_CURVE_SECP256K1, out, k, 32)) {
        return -1;
    }
    return 0;
}

int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    enum { PRIVATE_KEY_LEN = 32 };
    uint8_t raw_private_key[64] = {0};
    _Static_assert(sizeof(raw_private_key) >= PRIVATE_KEY_LEN, "raw_private_key[] is too small to fit private key");

    bool ok = CX_OK == os_derive_bip32_no_throw(CX_CURVE_256K1,
                                                bip32_path,
                                                bip32_path_len,
                                                raw_private_key,
                                                chain_code);
    ok = ok && CX_OK == cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                                          raw_private_key,
                                                          PRIVATE_KEY_LEN,
                                                          private_key);
    explicit_bzero(&raw_private_key, sizeof(raw_private_key));

    return ok ? 0 : -1;
}

int bip32_CKDpub(const serialized_extended_pubkey_t *parent,
                 uint32_t index,
                 serialized_extended_pubkey_t *child) {
    PRINT_STACK_POINTER();

    if (index >= BIP32_FIRST_HARDENED_CHILD) {
        return -1;  // can only derive unhardened children
    }

    if (parent->depth == 255) {
        return -1;  // maximum derivation depth reached
    }

    uint8_t I[64];

    {  // make sure that heavy memory allocations are freed as soon as possible

        uint8_t tmp[33 + 4];
        memcpy(tmp, parent->compressed_pubkey, sizeof(tmp) - sizeof(uint32_t));
        write_u32_be(tmp, 33, index);

        cx_hmac_sha512(parent->chain_code, 32, tmp, sizeof(tmp), I, 64);
    }

    uint8_t *I_L = &I[0];
    uint8_t *I_R = &I[32];

    // fail if I_L is not smaller than the group order n, but the probability is < 1/2^128
    int diff = 0;
    if (CX_OK != cx_math_cmp_no_throw(I_L, secp256k1_n, 32, &diff) || diff >= 0) {
        return -1;
    }

    uint8_t child_uncompressed_pubkey[65];

    {  // make sure that heavy memory allocations are freed as soon as possible
        // compute point(I_L)
        uint8_t P[65];
        if (0 > secp256k1_point(I_L, P)) {
            return -1;
        }

        uint8_t K_par[65];
        if (0 != crypto_get_uncompressed_pubkey(parent->compressed_pubkey, K_par)) {
            return -1;
        }
        // add K_par
        if (CX_OK != cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1,
                                                child_uncompressed_pubkey,
                                                P,
                                                K_par)) {
            return -1;  // the point at infinity is not a valid child pubkey (should never happen in
                        // practice)
        }
    }

    memmove(child->version, parent->version, MIN(4, sizeof(child->version)));
    child->depth = parent->depth + 1;

    uint32_t parent_fingerprint = crypto_get_key_fingerprint(parent->compressed_pubkey);

    write_u32_be(child->parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(child->child_number, 0, index);

    memcpy(child->chain_code, I_R, sizeof(child->chain_code));

    return crypto_get_compressed_pubkey(child_uncompressed_pubkey, child->compressed_pubkey);
}

void crypto_hash_update_zeros(cx_hash_t *hash_context, size_t n_zeros) {
    int ret = 32;
    static const uint8_t data[8] = { 0 };
    size_t i;

    for (i = 0; i < (n_zeros >> 3) && 32 == ret; ++i) {
        crypto_hash_update(hash_context, &data, 8);
    }
    for (i = 0; i < (n_zeros & 7) && 32 == ret; ++i) {
        crypto_hash_update(hash_context, &data, 1);
    }
}

#ifndef _NR_cx_hash_ripemd160
/** Missing in some SDKs, we implement it using the cxram section if needed. */
static size_t cx_hash_ripemd160(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    PRINT_STACK_POINTER();

    if (out_len < CX_RIPEMD160_SIZE) {
        return 0;
    }
    LEDGER_ASSERT(cx_ripemd160_init_no_throw((cx_ripemd160_t *) &G_cx) == CX_OK, "It never fails");
    LEDGER_ASSERT(cx_ripemd160_update((cx_ripemd160_t *) &G_cx, in, in_len) == CX_OK,
                  "It never fails");
    LEDGER_ASSERT(cx_ripemd160_final((cx_ripemd160_t *) &G_cx, out) == CX_OK, "It never fails");
    explicit_bzero((cx_ripemd160_t *) &G_cx, sizeof(cx_sha256_t));
    return CX_RIPEMD160_SIZE;
}
#endif  // _NR_cx_hash_ripemd160

void crypto_ripemd160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    cx_hash_ripemd160(in, inlen, out, 20);
}

void crypto_hash160(const uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    PRINT_STACK_POINTER();

    uint8_t buffer[32];
    cx_hash_sha256(in, inlen, buffer, 32);
    crypto_ripemd160(buffer, 32, out);
}

int crypto_get_uncompressed_pubkey(const uint8_t compressed_key[static 33],
                                   uint8_t out[static 65]) {
    PRINT_STACK_POINTER();

    uint8_t prefix = compressed_key[0];
    if (prefix != 0x02 && prefix != 0x03) {
        return -1;
    }

    uint8_t *x = &out[1], *y = &out[1 + 32];

    memmove(x, compressed_key + 1, 32);  // copy x

    // we use y for intermediate results, in order to save memory

    uint8_t e = 3;
    if (CX_OK != cx_math_powm_no_throw(y, x, &e, 1, secp256k1_p, 32)) {
        return -1;  // tmp = x^3 (mod p)
    }
    uint8_t scalar[32] = {0};
    scalar[31] = 7;
    if (CX_OK != cx_math_addm_no_throw(y, y, scalar, secp256k1_p, 32)) {
        return -1;  // tmp = x^3 + 7 (mod p)
    }
    if (CX_OK != cx_math_powm_no_throw(y, y, secp256k1_sqr_exponent, 32, secp256k1_p, 32)) {
        return -1;  // tmp = sqrt(x^3 + 7) (mod p)
    }

    // if the prefix and y don't have the same parity, take the opposite root (mod p)
    if (((prefix ^ y[31]) & 1) != 0) {
        if (CX_OK != cx_math_sub_no_throw(y, secp256k1_p, y, 32)) {
            return -1;
        }
    }

    out[0] = 0x04;
    return 0;
}

bool crypto_get_compressed_pubkey_at_path(const uint32_t bip32_path[],
                                          uint8_t bip32_path_len,
                                          uint8_t pubkey[static 33],
                                          uint8_t chain_code[]) {
    struct {
        uint8_t prefix;
        uint8_t raw_public_key[64];
        uint8_t chain_code[32];
    } keydata;

    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;

    bool ok = true;

    keydata.prefix = 0x04;  // uncompressed public keys always start with 04
    // derive private key according to BIP32 path
    ok = ok && 0 == crypto_derive_private_key(&private_key, keydata.chain_code, bip32_path, bip32_path_len);

    if (ok && chain_code != NULL) {
        memmove(chain_code, keydata.chain_code, 32);
    }

    // generate corresponding public key
    ok = ok && CX_OK == cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &public_key, &private_key, 1);
    memmove(keydata.raw_public_key, public_key.W + 1, sizeof(keydata.raw_public_key));

    // compute compressed public key
    ok = ok && 0 == crypto_get_compressed_pubkey((uint8_t *) &keydata, pubkey);

    // delete sensitive data
    explicit_bzero(keydata.chain_code, 32);
    explicit_bzero(&private_key, sizeof(private_key));

    return ok;
}

uint32_t crypto_get_key_fingerprint(const uint8_t pub_key[static 33]) {
    uint8_t key_rip[20];
    crypto_hash160(pub_key, 33, key_rip);

    return read_u32_be(key_rip, 0);
}

 uint32_t crypto_get_master_key_fingerprint() {
    uint8_t master_pub_key[33];
    uint32_t bip32_path[] = {};
    LEDGER_ASSERT(crypto_get_compressed_pubkey_at_path(bip32_path, 0, master_pub_key, NULL), "It never fails");
    return crypto_get_key_fingerprint(master_pub_key);
}

bool crypto_derive_symmetric_key(const char *label, size_t label_len, uint8_t key[static 32]) {
    // TODO: is there a better way?
    //       The label is a byte string in SLIP-0021, but os_derive_bip32_with_seed_no_throw
    //       accesses the `path` argument as an array of uint32_t, causing a device freeze if memory
    //       is not aligned.
    uint8_t label_copy[32] __attribute__((aligned(4)));

    memcpy(label_copy, label, MIN(label_len, sizeof(label_copy)));
    uint8_t raw_privkey[64]; // Needed because in the new SDK derived key could be up to 64 bytes long

    bool res = CX_OK == os_derive_bip32_with_seed_no_throw(HDW_SLIP21,
                                                           CX_CURVE_SECP256K1,
                                                           (uint32_t *) label_copy,
                                                           label_len,
                                                           raw_privkey,
                                                           NULL,
                                                           NULL,
                                                           0);
    if (res) {
        memcpy(key, raw_privkey, 32);
    }
    explicit_bzero(raw_privkey, sizeof(raw_privkey));
    return res;
}

// TODO: Split serialization from key derivation?
//       It might be difficult to have a clean API without wasting memory, as the checksum
//       needs to be concatenated to the data before base58 serialization.
int get_serialized_extended_pubkey_at_path(const uint32_t bip32_path[],
                                           uint8_t bip32_path_len,
                                           uint32_t bip32_pubkey_version,
                                           char out[static MAX_SERIALIZED_PUBKEY_LENGTH + 1]) {
    // find parent key's fingerprint and child number
    uint32_t parent_fingerprint = 0;
    uint32_t child_number = 0;
    if (bip32_path_len > 0) {
        // here we reuse the storage for the parent keys that we will later use
        // for the response, in order to save memory

        uint8_t parent_pubkey[33];
        if (!crypto_get_compressed_pubkey_at_path(bip32_path, bip32_path_len - 1, parent_pubkey, NULL)) {
            return -1;
        }

        parent_fingerprint = crypto_get_key_fingerprint(parent_pubkey);
        child_number = bip32_path[bip32_path_len - 1];
    }

    struct {
        serialized_extended_pubkey_t ext_pubkey;
        uint8_t checksum[4];
    } ext_pubkey_check;  // extended pubkey and checksum

    serialized_extended_pubkey_t *ext_pubkey = &ext_pubkey_check.ext_pubkey;

    write_u32_be(ext_pubkey->version, 0, bip32_pubkey_version);
    ext_pubkey->depth = bip32_path_len;
    write_u32_be(ext_pubkey->parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(ext_pubkey->child_number, 0, child_number);

    if (!crypto_get_compressed_pubkey_at_path(bip32_path,
                                              bip32_path_len,
                                              ext_pubkey->compressed_pubkey,
                                              ext_pubkey->chain_code)) {
        return -1;
    }
    crypto_get_checksum((uint8_t *) ext_pubkey, 78, ext_pubkey_check.checksum);

    int serialized_pubkey_len =
        base58_encode((uint8_t *) &ext_pubkey_check, 78 + 4, out, MAX_SERIALIZED_PUBKEY_LENGTH);

    if (serialized_pubkey_len > 0) {
        out[serialized_pubkey_len] = '\0';
    }
    return serialized_pubkey_len;
}

int base58_encode_address(const uint8_t in[20], uint32_t version, char *out, size_t out_len) {
    uint8_t tmp[4 + 20 + 4];  // version + max_in_len + checksum

    uint8_t version_len;
    if (version < 256) {
        tmp[0] = (uint8_t) version;
        version_len = 1;
    } else if (version < 65536) {
        write_u16_be(tmp, 0, (uint16_t) version);
        version_len = 2;
    } else {
        write_u32_be(tmp, 0, version);
        version_len = 4;
    }

    memcpy(tmp + version_len, in, 20);
    crypto_get_checksum(tmp, version_len + 20, tmp + version_len + 20);
    return base58_encode(tmp, version_len + 20 + 4, out, out_len);
}

int crypto_ecdsa_sign_sha256_hash_with_key(const uint32_t bip32_path[],
                                           size_t bip32_path_len,
                                           const uint8_t hash[static 32],
                                           uint8_t out[static MAX_DER_SIG_LEN],
                                           uint32_t *info) {
    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    uint32_t info_internal = 0;

    size_t sig_len = MAX_DER_SIG_LEN;

    bool ok = 0 == crypto_derive_private_key(&private_key, chain_code, bip32_path, bip32_path_len);
    ok = ok && CX_OK == cx_ecdsa_sign_no_throw(&private_key,
                                               CX_RND_RFC6979,
                                               CX_SHA256,
                                               hash,
                                               32,
                                               out,
                                               &sig_len,
                                               &info_internal);

    explicit_bzero(&private_key, sizeof(private_key));

    if (!ok) {
        // unexpected error when signing
        return -1;
    }

    if (info != NULL) {
        *info = info_internal;
    }

    return (int)sig_len;
}

void crypto_tr_tagged_hash_init(cx_sha256_t *hash_context, const uint8_t *tag, uint16_t tag_len) {
    // we recycle the input to save memory (will reinit later)
    cx_sha256_init(hash_context);

    uint8_t hashtag[32];
    crypto_hash_update(&hash_context->header, tag, tag_len);
    crypto_hash_digest(&hash_context->header, hashtag, sizeof(hashtag));

    cx_sha256_init(hash_context);
    crypto_hash_update(&hash_context->header, hashtag, sizeof(hashtag));
    crypto_hash_update(&hash_context->header, hashtag, sizeof(hashtag));
}

static void crypto_tr_tagged_hash(const uint8_t *tag,
                                  uint16_t tag_len,
                                  const uint8_t *data,
                                  uint16_t data_len,
                                  uint8_t out[static 32]) {
    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);

    crypto_tr_tagged_hash_init(&hash_context, tag, tag_len);

    crypto_hash_update(&hash_context.header, data, data_len);
    crypto_hash_digest(&hash_context.header, out, 32);
}

static int crypto_tr_lift_x(const uint8_t x[static 32], uint8_t out[static 65]) {
    // save memory by reusing output buffer for intermediate results
    uint8_t *y = out + 1 + 32;
    // we use the memory for the x-coordinate of the output as a temporary variable
    uint8_t *c = out + 1;

    // c = x^3 (mod p)
    uint8_t e = 3;
    if (CX_OK != cx_math_powm_no_throw(c, x, &e, 1, secp256k1_p, 32)) {
        return -1;
    }

    // c = x^3 + 7 (mod p)
    uint8_t scalar[32] = {0};
    scalar[31] = 7;
    if (CX_OK != cx_math_addm_no_throw(c, c, scalar, secp256k1_p, 32)) {
        return -1;
    }

    // y = sqrt(x^3 + 7) (mod p)
    if (CX_OK != cx_math_powm_no_throw(y, c, secp256k1_sqr_exponent, 32, secp256k1_p, 32)) {
        return -1;
    }

    // sanity check: fail if y * y % p != x^3 + 7
    uint8_t y_2[32];
    e = 2;
    if (CX_OK != cx_math_powm_no_throw(y_2, y, &e, 1, secp256k1_p, 32)) { // y^2 (mod p)
        return -1;
    }

    int diff = 1;
    if (CX_OK != cx_math_cmp_no_throw(y_2, c, 32, &diff) || diff != 0) {
        return -1;
    }

    if (y[31] & 1) {
        // y must be even: take the negation
        if (CX_OK != cx_math_sub_no_throw(out + 1 + 32, secp256k1_p, y, 32)) {
            return -1;
        }
    }

    // add the 0x04 prefix; copy x verbatim
    out[0] = 0x04;
    memcpy(out + 1, x, 32);

    return 0;
}

// Like taproot_tweak_pubkey of BIP0341, with empty string h
// TODO: should it recycle pubkey also for the output (like crypto_tr_tweak_seckey below)?
int crypto_tr_tweak_pubkey(uint8_t pubkey[static 32], uint8_t *y_parity, uint8_t out[static 32]) {
    uint8_t t[32];

    crypto_tr_tagged_hash(BIP0341_taptweak_tag, sizeof(BIP0341_taptweak_tag), pubkey, 32, t);

    // fail if t is not smaller than the curve order
    int diff = 1;
    if (CX_OK != cx_math_cmp_no_throw(t, secp256k1_n, 32, &diff) || diff >= 0) {
        return -1;
    }

    uint8_t Q[65];

    uint8_t lifted_pubkey[65];
    if (crypto_tr_lift_x(pubkey, lifted_pubkey) < 0) {
        return -1;
    }

    if (0 > secp256k1_point(t, Q)) {
        // point at infinity, or error
        return -1;
    }

    if (CX_OK != cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1, Q, Q, lifted_pubkey)) {
        return -1;  // error, or point at Infinity
    }

    *y_parity = Q[64] & 1;
    memcpy(out, Q + 1, 32);
    return 0;
}

// Like taproot_tweak_seckey of BIP0341, with empty string h
int crypto_tr_tweak_seckey(uint8_t seckey[static 32]) {
    uint8_t P[65];

    bool ok = 0 == secp256k1_point(seckey, P);

    if (P[64] & 1) {
        // odd y, negate the secret key
        ok = ok && CX_OK == cx_math_sub_no_throw(seckey, secp256k1_n, seckey, 32);
    }

    uint8_t t[32];
    crypto_tr_tagged_hash(BIP0341_taptweak_tag,
                            sizeof(BIP0341_taptweak_tag),
                            &P[1],  // P[1:33] is x(P)
                            32,
                            t);

    // fail if t is not smaller than the curve order
    int diff = 1;
    ok = ok && CX_OK == cx_math_cmp_no_throw(t, secp256k1_n, 32, &diff);
    ok = ok && diff < 0;

    ok = ok && CX_OK == cx_math_addm_no_throw(seckey, seckey, t, secp256k1_n, 32);
    explicit_bzero(&P, sizeof(P));

    return ok ? 0 : -1;
}

#endif // SKIP_FOR_CMOCKA

/*****************************************************************************
 * FUNTIONS COVERED BY CMOCKA UNIT TESTS
 *****************************************************************************/

// TODO: missing unit tests
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    cx_hash_sha256(in, in_len, buffer, 32);
    cx_hash_sha256(buffer, 32, buffer, 32);
    memmove(out, buffer, 4);
}

int crypto_get_compressed_pubkey(const uint8_t uncompressed_key[static 65],
                                 uint8_t out[static 33]) {
    if (uncompressed_key[0] != 0x04) {
        return -1;
    }
    out[0] = (uncompressed_key[64] % 2 == 1) ? 0x03 : 0x02;
    memmove(out + 1, uncompressed_key + 1, 32);  // copy x
    return 0;
}

int validate_serialized_extended_pubkey(const char *pubkey,
                                        const uint32_t bip32_path[],
                                        int bip32_path_len,
                                        uint32_t bip32_pubkey_version) {
    if (!pubkey || bip32_path_len < -1 || bip32_path_len > MAX_BIP32_PATH_STEPS ||
        (bip32_path_len > 0 && !bip32_path)) {
        return EXTENDED_PUBKEY_INVALID_ARGUMENT;
    }

    size_t pubkey_len = strnlen(pubkey, MAX_SERIALIZED_PUBKEY_LENGTH + 1);
    if (!pubkey_len || pubkey_len > MAX_SERIALIZED_PUBKEY_LENGTH) {
        return EXTENDED_PUBKEY_INVALID_ARGUMENT;
    }

    serialized_extended_pubkey_check_t ext_pubkey_check;  // extended pubkey and checksum
    serialized_extended_pubkey_t *ext_pubkey = &ext_pubkey_check.serialized_extended_pubkey;

    if (sizeof(ext_pubkey_check) !=
        base58_decode(pubkey, pubkey_len, (uint8_t*)&ext_pubkey_check, sizeof(ext_pubkey_check))) {
        return EXTENDED_PUBKEY_INVALID_BASE58_CODE;
    }

    uint8_t checksum[4];
    crypto_get_checksum((uint8_t *)ext_pubkey, sizeof(serialized_extended_pubkey_t), checksum);

    if (!memeq(checksum, ext_pubkey_check.checksum, sizeof(checksum))) {
        return EXTENDED_PUBKEY_INVALID_CHECKSUM;
    }

    if (read_u32_be(ext_pubkey->version, 0) != bip32_pubkey_version) {
        return EXTENDED_PUBKEY_INVALID_VERSION;
    }

    if (ext_pubkey->depth == 0) {
        if (read_u32_be(ext_pubkey->child_number, 0) != 0) {
            return EXTENDED_PUBKEY_INVALID_CHILD_NUMBER;
        } else if (read_u32_be(ext_pubkey->parent_fingerprint, 0) != 0) {
            return EXTENDED_PUBKEY_INVALID_PARENT_FINGERPRINT;
        }
    }

    if (bip32_path_len > 0) {
        uint32_t child_number = !bip32_path_len ? 0 : bip32_path[bip32_path_len - 1];
        if (ext_pubkey->depth != bip32_path_len) {
            return EXTENDED_PUBKEY_INVALID_DEPTH;
        } else if (read_u32_be(ext_pubkey->child_number, 0) != child_number) {
            return EXTENDED_PUBKEY_INVALID_CHILD_NUMBER;
        }
    }

    uint8_t prefix = ext_pubkey->compressed_pubkey[0];
    if (prefix != 0x02 && prefix != 0x03) {
        return EXTENDED_PUBKEY_INVALID_PREFIX;
    }

    return EXTENDED_PUBKEY_VALID;
}
