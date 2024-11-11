#pragma once

#ifdef HAVE_LIQUID

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include "decorators.h"

// Prefix of confidential address
#define LIQUID_ADDR_PREFIX_CA

/**
 * Creates a confidential address.
 *
 * @param[in] in
 *   Buffer containing input payload.
 * @param in_len
 *   Length of the payload in bytes.
 * @param[in] prefix
 *   The confidential address prefix byte.
 * @param[in] version
 *   The confidential address version byte.
 * @param[in] pub_key
 *   The blinding public key to associate with ``address``.
 * @param[in] pub_key_len
 *   The length of ``pub_key`` in bytes; must be 33 bytes.
 * @param[out] out
 *   Pointer to output string buffer.
 * @param[in] out_len
 *   Maximum length to write in output byte buffer.
 *
 * @return the length of the encoded output on success, -1 on failure (that is, if the output
 *   would be longer than out_len).
 */
WARN_UNUSED_RESULT int liquid_encode_address_base58(const uint8_t *in,
                                                    size_t in_len,
                                                    uint32_t prefix,
                                                    uint32_t version,
                                                    const uint8_t *pub_key,
                                                    size_t pub_key_len,
                                                    char *out,
                                                    size_t out_len);

/**
 * Creates a confidential SegWit address.
 *
 * @param[in] witprog
 *   Buffer containing witness program.
 * @param[in] witprog_len
 *   Length of a witness program in bytes.
 * @param[in] prefix
 *   Address prefix, a text string.
 * @param version
 *   Version of witness program.
 * @param pub_key
 *   The blinding public key to associate with ``address``.
 * @param pub_key_len
 *   The length of ``pub_key`` in bytes; must be 33 bytes.
 * @param[out] out
 *   Pointer to output string buffer.
 * @param[in] out_len
 *   Maximum length to write in output byte buffer.
 *
 * @return the length of the encoded output on success, -1 on failure (that is, if the output
 *   would be longer than out_len).
 */
WARN_UNUSED_RESULT int liquid_encode_address_segwit(const uint8_t *witprog,
                                                    size_t witprog_len,
                                                    const char *prefix,
                                                    uint32_t version,
                                                    const uint8_t *pub_key,
                                                    size_t pub_key_len,
                                                    char *out,
                                                    size_t out_len);

#endif  // HAVE_LIQUID
