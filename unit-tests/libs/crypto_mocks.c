#include <stdint.h>
#include "crypto_mocks.h"
#include "sha-256.h"
#include "cx.h"
#include "util.h"

void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    calc_sha_256(buffer, in, in_len);
    calc_sha_256(buffer, buffer, 32);
    memmove(out, buffer, 4);
}

/**
 * Mock implementation, not to be used outside test environment.
 */

__attribute__((weak)) int cx_hash_sha256(const unsigned char WIDE *in,
                                         unsigned int len, unsigned char *out,
                                         unsigned int out_len) {
    if(out_len >= SIZE_OF_SHA_256_HASH) {
        calc_sha_256(out, in, len);
    } else {
        memset(out, 0, out_len);
    }
    return 0;
}

/**
 * Mock implementation, not to be used outside test environment.
 */
__attribute__((weak)) cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    if (hash) {
        memset(hash, 0, sizeof(cx_sha256_t));
        hash->header.algo = CX_SHA256;
        sha_256_init(&hash->sha_256, hash->hash);
        return CX_OK;
    }
    return CX_INTERNAL_ERROR;
}

/**
 * Mock implementation, not to be used outside test environment.
 */
__attribute__((weak)) cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode, const uint8_t *in,
                          size_t len, uint8_t *out, size_t out_len) {
    if (hash && CX_SHA256 == hash->algo) {
        cx_sha256_t *ctx = (cx_sha256_t*)hash;
        if (0 == mode) {
            if (in) {
                sha_256_write(&ctx->sha_256, in, len);
                return CX_OK;
            }
        } else if (CX_LAST == mode) {
            if (in && len) {
                sha_256_write(&ctx->sha_256, in, len);
            }
            if (out && out_len >= SIZE_OF_SHA_256_HASH) {
                uint8_t *p_result = sha_256_close(&ctx->sha_256);
                memcpy(out, p_result, SIZE_OF_SHA_256_HASH);
                return CX_OK;
            }
        }
    }
    return CX_INTERNAL_ERROR;
}

/**
 * Mock implementation, not to be used outside test environment.
 */
__attribute__((weak)) bool sha256_midstate_reversed(const cx_sha256_t* sha256_context,
                                                    uint8_t out[32]) {
    if (sha256_context && CX_SHA256 == sha256_context->header.algo) {
        sha_256_midstate(&sha256_context->sha_256, out);
        reverse_inplace(out, 32);
        return true;
    }
    return false;
}

#ifdef __clang__
/**
 * Mock implementation, not to be used outside test environment.
 */
void __attribute__((weak)) explicit_bzero(void *ptr, size_t len) {
    memset(ptr, 0, len);
    *(volatile uint8_t*)ptr = *(volatile uint8_t*)ptr;
}
#endif