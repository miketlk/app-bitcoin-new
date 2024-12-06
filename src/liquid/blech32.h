#pragma once
#ifdef HAVE_LIQUID

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include "decorators.h"

/**
 * Encodes address using Blech32 encoding.
 *
 * @param[out] output
 *   Pointer to output string buffer.
 * @param[in] output_limit
 *   Maximum length to write in output byte buffer.
 * @param[in] hrp
 *   Human readable part of an address.
 * @param[in] witver
 *   Version of witness program.
 * @param[in] witprog
 *   Buffer containing witness program.
 * @param[in] witprog_len
 *   Length of a witness program in bytes.
 *
 * @return number of bytes written to the output buffer, 0 if failure.
 */
WARN_UNUSED_RESULT int blech32_addr_encode(char *output,
                                           size_t output_limit,
                                           const char *hrp,
                                           uint8_t witver,
                                           const uint8_t *witprog,
                                           size_t witprog_len);

/**
 * Decodes address using Blech32 encoding.
 *
 * @param[out] witver
 *   Pointer to variable receiving version of the witness program.
 * @param[out] witdata
 *   Pointer to buffer receiving the witness program.
 * @param[in] witdata_limit
 *   Maximum length to write in ``witness program`` byte buffer.
 * @param[out] witdata_len
 *   Pointer to variable receiving length of the witness program.
 * @param[in] hrp
 *   Expected human readable part, to be compared with decoded value.
 * @param[in] addr
 *   Address to decode.
 *
 * @return nonzero if successful, 0 if failure.
 */
WARN_UNUSED_RESULT int blech32_addr_decode(uint8_t *witver,
                                           uint8_t *witdata,
                                           size_t witdata_limit,
                                           size_t *witdata_len,
                                           const char *hrp,
                                           const char *addr);

#endif // HAVE_LIQUID