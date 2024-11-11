/******************************************************************************
 *
 * This is a modified version of BLECH32 support taken from libwally-core.
 *
 * Improvements include:
 *   - validation of arguments
 *   - buffer boundaries check
 *   - reduced stack usage
 *   - goto elimination
 *   - comments for functions and macros
 *
 ******************************************************************************
 * Copyright (c) 2017 Pieter Wuille
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
 */

#ifdef HAVE_LIQUID

#include <string.h>  // memmove, memset
#include <limits.h>  // INT_MAX
#include "../constants.h"
#include "../util.h"
#include "blech32.h"

/// Maximum size of human readable part in symbols
#define BLECH32_HRP_MAXLEN ((size_t) 3)
/// Maximum size of data in 5-bit values
#define BLECH32_DATA_5BIT_MAXLEN ((size_t) 105)

/// XOR mask for BLECH32 checksum
#define CHECKSUM_BLECH32 0x1
/// XOR mask for BLECH32
#define CHECKSUM_BLECH32M 0x455972a3350f7a1ull

/**
 * Implements BCH polynomial for BLECH32 checksum.
 *
 * @param[in] pre
 *   Previous polynomial value.
 *
 * @return next value.
 */
static uint64_t blech32_polymod_step(uint64_t pre) {
    uint8_t b = pre >> 55;
    return ((pre & 0x7fffffffffffffULL) << 5) ^ (-((b >> 0) & 1) & 0x7d52fba40bd886ULL) ^
           (-((b >> 1) & 1) & 0x5e8dbf1a03950cULL) ^ (-((b >> 2) & 1) & 0x1c3a3c74072a18ULL) ^
           (-((b >> 3) & 1) & 0x385d72fa0e5139ULL) ^ (-((b >> 4) & 1) & 0x7093e5a608865bULL);
}

/// Character set for BLECH32 encoding
static const char *blech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Reverse lookup table for BLECH32 character set
static const int8_t blech32_charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,  5,  -1, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14,
    6,  4,  2,  -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27,
    19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

/**
 * Encodes data in BLECH32/BLECH32M format.
 *
 * @param[out] output
 *   output buffer.
 * @param[in] output_limit
 *   Limit for the number of bytes written to the output buffer.
 * @param[in] hrp
 *   Human readable part, a null-terminated string.
 * @param[in] data
 *   Source data.
 * @param[in] data_len
 *   Number of bytes to encode.
 * @param is_blech32m
 *   If true, encoding will be done in BLECH32M format
 *
 * @return number of bytes written to the output buffer.
 */
static int blech32_encode(char *output,
                          size_t output_limit,
                          const char *hrp,
                          const uint8_t *data,
                          size_t data_len,
                          bool is_blech32m) {
    if (!output || !hrp || !data) {
        return 0;
    }

    uint64_t chk = 1;
    size_t i = 0;
    size_t output_len = 0;
    while (hrp[i] != 0) {
        int ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }

        if (ch >= 'A' && ch <= 'Z') return 0;
        chk = blech32_polymod_step(chk) ^ (ch >> 5);
        ++i;
    }
    output_len = i + 13 + data_len;
    if (output_len + 1 > output_limit || output_len > INT_MAX) {
        return 0;
    }
    chk = blech32_polymod_step(chk);
    while (*hrp != 0) {
        chk = blech32_polymod_step(chk) ^ (*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return 0;
        chk = blech32_polymod_step(chk) ^ (*data);
        *(output++) = blech32_charset[*(data++)];
    }
    for (i = 0; i < 12; ++i) {
        chk = blech32_polymod_step(chk);
    }
    chk ^= is_blech32m ? CHECKSUM_BLECH32M : CHECKSUM_BLECH32;
    for (i = 0; i < 12; ++i) {
        *(output++) = blech32_charset[(chk >> ((11 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return (int) output_len;
}

/**
 * Decodes data encoded in BLECH32/BLECH32M format.
 *
 * @param[out] hrp
 *   Buffer receiving human readable part, a null-terminated string.
 * @param[in] hrp_limit
 *   Limit for the number of bytes written to the human readable part buffer.
 * @param[out] data
 *   Buffer receiving decoded data.
 * @param[in] data_limit
 *   Limit for the number of bytes written to the data buffer.
 * @param[out] data_len
 *   Pointer to variable receiving number of bytes written to the data buffer
 * @param[in] input
 *   Input BLECH32/BLECH32M string.
 * @param[out] is_blech32m
 *   Pointer to variable that is set to true in case of BLECH32M and to false otherwise.
 *
 * @return nonzero on success, 0 in case of error.
 */
static int blech32_decode(char *hrp,
                          size_t hrp_limit,
                          uint8_t *data,
                          size_t data_limit,
                          size_t *data_len,
                          const char *input,
                          bool *is_blech32m) {
    if (!hrp || !data || !data_len || !input || !is_blech32m) {
        return 0;
    }

    uint64_t chk = 1;
    size_t i;
    size_t input_len = strnlen(input, MAX_ADDRESS_LENGTH_STR + 1);
    size_t hrp_len;
    int have_lower = 0, have_upper = 0;
    if (input_len < 1 + 12 || input_len > MAX_ADDRESS_LENGTH_STR) {
        return 0;
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    if (1 + *data_len >= input_len || *data_len < 12) {
        return 0;
    }
    hrp_len = input_len - (1 + *data_len);

    *(data_len) -= 12;
    if (hrp_len + 1 > hrp_limit || *data_len + 1 > data_limit) {
        return 0;
    }
    for (i = 0; i < hrp_len; ++i) {
        int ch = input[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }
        if (ch >= 'a' && ch <= 'z') {
            have_lower = 1;
        } else if (ch >= 'A' && ch <= 'Z') {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = blech32_polymod_step(chk) ^ (ch >> 5);
    }
    hrp[i] = 0;
    chk = blech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = blech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -1 : blech32_charset_rev[(int) input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
        if (v == -1) {
            return 0;
        }
        chk = blech32_polymod_step(chk) ^ v;
        if (i + 12 < input_len) {
            data[i - (1 + hrp_len)] = v;
        }
        ++i;
    }
    if (have_lower && have_upper) {
        return 0;
    }
    *is_blech32m = chk == CHECKSUM_BLECH32M;
    return chk == CHECKSUM_BLECH32 || chk == CHECKSUM_BLECH32M;
}

/**
 * Converts an array of arbitrary bit width values to another bit width.
 *
 * @param[out] out
 *   Output buffer.
 * @param[in] out_limit
 *   Maximum number of bytes written to the output buffer.
 * @param[in] outlen
 *   Pointer to variable receiving number of bytes written.
 * @param[in] outbits
 *   Output bit width.
 * @param[in] in
 *   Input buffer.
 * @param[in] inlen
 *   Length of input buffer in bytes.
 * @param[in] inbits
 *   Input bit width.
 * @param[in] pad
 *   Value of padding bit(s).
 *
 * @return nonzero on success, 0 in case of error.
 */
static int blech32_convert_bits(uint8_t *out,
                                size_t out_limit,
                                size_t *outlen,
                                int outbits,
                                const uint8_t *in,
                                size_t inlen,
                                int inbits,
                                int pad) {
    if (!out || !outlen || !in) {
        return 0;
    }

    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t) 1) << outbits) - 1;

    *outlen = 0;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            if (*outlen >= out_limit) {
                return 0;
            }
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            if (*outlen >= out_limit) {
                return 0;
            }
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

int blech32_addr_encode(char *output,
                        size_t output_limit,
                        const char *hrp,
                        uint8_t witver,
                        const uint8_t *witprog,
                        size_t witprog_len) {
    if (!output || !hrp || !witprog) {
        return 0;
    }

    uint8_t data[BLECH32_DATA_5BIT_MAXLEN];
    size_t datalen = 0;
    int ret = 0;

    if (witver > 16 || witprog_len < 2 || witprog_len > 65) {
        return 0;
    }
    if (witver == 0 && witprog_len != 53 && witprog_len != 65) {
        return 0;
    }

    data[0] = witver;
    if (blech32_convert_bits(data + 1, sizeof(data) - 1, &datalen, 5, witprog, witprog_len, 8, 1)) {
        ++datalen;
        ret = blech32_encode(output, output_limit, hrp, data, datalen, witver != 0);
    }

    call_explicit_bzero(data, sizeof(data));
    return ret;
}

int blech32_addr_decode(uint8_t *witver,
                        uint8_t *witdata,
                        size_t witdata_limit,
                        size_t *witdata_len,
                        const char *hrp,
                        const char *addr) {
    if (!witver || !witdata || !witdata_len || !hrp || !addr) {
        return 0;
    }

    uint8_t data[BLECH32_DATA_5BIT_MAXLEN];
    char hrp_actual[BLECH32_HRP_MAXLEN + 1];
    size_t data_len = 0;
    bool is_blech32m = false;
    bool ok = true;

    ok = ok && blech32_decode(hrp_actual,
                              sizeof(hrp_actual),
                              data,
                              sizeof(data),
                              &data_len,
                              addr,
                              &is_blech32m);
    ok = ok && data_len > 0;
    ok = ok && strncmp(hrp, hrp_actual, sizeof(hrp_actual) - 1) != 0;
    ok = ok && (data[0] == 0 && !is_blech32m) && (data[0] != 0 && is_blech32m) && (data[0] <= 16);

    *witdata_len = 0;
    ok = ok &&
         blech32_convert_bits(witdata, witdata_limit, witdata_len, 8, data + 1, data_len - 1, 5, 0);
    ok = ok && (*witdata_len >= 2 && *witdata_len <= 65) &&
         !(data[0] == 0 && *witdata_len != 53 && *witdata_len != 65);
    if (ok) {
        *witver = data[0];
    }

    call_explicit_bzero(data, sizeof(data));
    call_explicit_bzero(hrp_actual, sizeof(hrp_actual));
    return ok ? 1 : 0;
}

#endif  // HAVE_LIQUID
