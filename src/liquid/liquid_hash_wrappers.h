#pragma once
#ifdef HAVE_LIQUID

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include "cx.h"
#include "write.h"
#include "decorators.h"

/**
 * Convenience wrapper for cx_sha256_init_no_throw.
 *
 * @param[out] sha256_context
 *   The context of SHA-256, which needs to be initialized.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT static inline bool hash_init_sha256(cx_sha256_t *sha256_context) {
    return CX_OK == cx_sha256_init_no_throw(sha256_context);
}

/**
 * Convenience wrapper for cx_hash to add some data to an initialized hash context.
 *
 * @param[in] hash_context
 *   The context of the hash, which must already be initialized.
 * @param[in] in
 *   Pointer to the data to be added to the hash computation.
 * @param[in] in_len
 *   Size of the passed data.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT static inline bool hash_update(cx_hash_t *hash_context,
                                                  const void *in,
                                                  size_t in_len) {
    return CX_OK == cx_hash_no_throw(hash_context, 0, in, in_len, NULL, 0);
}

/**
 * Convenience wrapper for hash_update, updating a hash with an uint8_t.
 *
 * @param[in] hash_context
 *  The context of the hash, which must already be initialized.
 * @param[in] data
 *  The uint8_t to be added to the hash.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT static inline bool hash_update_u8(cx_hash_t *hash_context, uint8_t data) {
    return hash_update(hash_context, &data, 1);
}

/**
 * Updates hash passing bytes in reverse order.
 *
 * @param[in] hash_context
 *   The context of the hash, which must already be initialized.
 * @param[in] in
 *   Pointer to the data to be added to the hash computation.
 * @param[in] in_len
 *   Size of the passed data.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT static inline bool hash_update_reversed(cx_hash_t *hash_context,
                                                           const void *in,
                                                           size_t in_len) {
    const uint8_t *p_in = (const uint8_t *) in + in_len - 1;
    int res = (int) true;
    for (size_t i = 0; i < in_len; ++i) {
        res &= (int) hash_update_u8(hash_context, *p_in--);
    }
    return !!res;
}

/**
 * Convenience wrapper for hash_update, updating a hash with an uint32_t,
 * encoded in big-endian.
 *
 * @param[in] hash_context
 *  The context of the hash, which must already be initialized.
 * @param[in] data
 *  The uint32_t to be added to the hash.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT static inline bool hash_update_u32_be(cx_hash_t *hash_context, uint32_t data) {
    uint8_t buf[4];
    write_u32_be(buf, 0, data);
    return hash_update(hash_context, &buf, sizeof(buf));
}

/**
 * Convenience wrapper for hash_update, updating a hash with an uint32_t,
 * encoded in little-endian.
 *
 * @param[in] hash_context
 *  The context of the hash, which must already be initialized.
 * @param[in] data
 *  The uint32_t to be added to the hash.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT static inline bool hash_update_u32_le(cx_hash_t *hash_context, uint32_t data) {
    uint8_t buf[4];
    write_u32_le(buf, 0, data);
    return hash_update(hash_context, &buf, sizeof(buf));
}

/**
 * Convenience wrapper for cx_hash to compute the final hash, without adding any extra data
 * to the hash context.
 *
 * @param[in] hash_context
 *   The context of the hash, which must already be initialized.
 * @param[in] out
 *   Pointer to the output buffer for the result.
 * @param[in] out_len
 *   Size of output buffer, which must be large enough to contain the result.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT static inline bool hash_digest(cx_hash_t *hash_context,
                                                  uint8_t *out,
                                                  size_t out_len) {
    return CX_OK == cx_hash_no_throw(hash_context, CX_LAST, NULL, 0, out, out_len);
}

#endif  // HAVE_LIQUID