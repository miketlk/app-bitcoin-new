/******************************************************************************
 *
 * Confidential address support is partially based on libwally-core:
 *
 ******************************************************************************
 *
 *     Copyright Jon Griffiths (Blockstream) 2016.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#ifdef HAVE_LIQUID

#include <string.h>  // memmove, memset
#include "liquid_addr.h"
#include "../util.h"
#include "../common/buffer.h"
#include "../common/read.h"
#include "../common/write.h"
#include "../common/base58.h"
#include "../common/segwit_addr.h"
#include "blech32.h"

/// The length of a public key used for EC signing
#define EC_PUBLIC_KEY_LEN 33
/// RIPEMD160 message digest size
#define HASH160_LEN 20
/// The number of extra bytes required to hold a base58 checksum
#define BASE58_CHECKSUM_LEN 4
/// Length for SHA-256 result in bytes
#define SHA256_LEN 32

int liquid_encode_address_base58(const uint8_t *in,
                                 size_t in_len,
                                 uint32_t prefix,
                                 uint32_t version,
                                 const uint8_t *pub_key,
                                 size_t pub_key_len,
                                 char *out,
                                 size_t out_len) {
    if (!in || in_len != HASH160_LEN || prefix > 0xFF || version > 0xFF || !pub_key ||
        pub_key_len != EC_PUBLIC_KEY_LEN || !out || !out_len) {
        return -1;
    }

    uint8_t data[2 + EC_PUBLIC_KEY_LEN + HASH160_LEN + BASE58_CHECKSUM_LEN];
    buffer_t buf = buffer_create(data, sizeof(data));
    bool ok = true;
    int addr_len = -1;

    ok = ok && buffer_write_u8(&buf, prefix & 0xFF);
    ok = ok && buffer_write_u8(&buf, version & 0xFF);
    ok = ok && buffer_write_bytes(&buf, pub_key, pub_key_len);
    ok = ok && buffer_write_bytes(&buf, in, in_len);
    ok = ok && buffer_write_u32(&buf, base58_checksum(data, buf.offset), BE);

    if (ok) {
        addr_len = base58_encode(data, buf.offset, out, out_len - 1);
        if (addr_len >= 0 && (size_t) addr_len < out_len) {
            out[addr_len] = '\0';
        } else {
            ok = false;
        }
    }

    // Zeroise temporary buffer and return
    call_explicit_bzero(data, sizeof(data));
    return ok ? addr_len : -1;
}

int liquid_encode_address_segwit(const uint8_t *witprog,
                                 size_t witprog_len,
                                 const char *prefix,
                                 uint32_t version,
                                 const uint8_t *pub_key,
                                 size_t pub_key_len,
                                 char *out,
                                 size_t out_len) {
    if (!witprog || !prefix || version > 0xFF || !pub_key || !out || !out_len) {
        return -1;
    }

    uint8_t data[EC_PUBLIC_KEY_LEN + SHA256_LEN];
    buffer_t buf = buffer_create(data, sizeof(data));
    bool ok = true;
    int addr_len = 0;

    ok = ok && buffer_write_bytes(&buf, pub_key, pub_key_len);
    ok = ok && buffer_write_bytes(&buf, witprog, witprog_len);
    ok = ok && (addr_len = blech32_addr_encode(out, out_len, prefix, version, data, buf.offset));

    call_explicit_bzero(data, sizeof(data));
    return ok ? addr_len : -1;
}

#endif  // HAVE_LIQUID
