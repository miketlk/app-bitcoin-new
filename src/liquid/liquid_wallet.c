#ifdef HAVE_LIQUID

#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "../common/base58.h"
#include "../common/bip32.h"
#include "../common/buffer.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/segwit_addr.h"
#include "../common/wallet.h"
#include "util.h"

#include "../cxram_stash.h"

#include "../boilerplate/sw.h"

#include "../debug-helpers/debug.h"

#ifndef SKIP_FOR_CMOCKA
#include "../crypto.h"
#else
// disable problematic macros when compiling unit tests with CMOCKA
#define PIC(x) (x)
#endif

// Allow overriding Makefile constants for tests using global variables
#if defined(SKIP_FOR_CMOCKA) && !defined(BIP32_PUBKEY_VERSION) && !defined(BIP32_PRIVKEY_VERSION)
    extern uint32_t BIP32_PUBKEY_VERSION;
    extern uint32_t BIP32_PRIVKEY_VERSION;
#endif

/// Maximum length of blinding key returned token prefix in characters
#define TOKEN_PREFIX_LEN 7

/// Bits specifying used characters
typedef enum {
    // BASIC CATEGORIES /////////////////////////////////////////////
    /// Numbers 0...9
    CHARSET_NUM = 1 << 0,
    /// Lowercase latin letters a...f
    CHARSET_ALPHA_AF_LOW = 1 << 1,
    /// Lowercase latin letters g...z
    CHARSET_ALPHA_GZ_LOW = 1 << 2,
    /// Uppercase latin letters a...f
    CHARSET_ALPHA_AF_UP = 1 << 3,
    /// Uppercase latin letters g...z
    CHARSET_ALPHA_GZ_UP = 1 << 4,
    /// Brackets ()
    CHARSET_BRACKETS = 1 << 5,
    /// Other characters
    CHARSET_OTHER = 1 << 6,

    // COMBINATIONS OT TRAITS ///////////////////////////////////////
    /// Lowercase hexadecimal numbers
    CHARSET_HEX_LOW = (CHARSET_NUM|CHARSET_ALPHA_AF_LOW),
    /// Lowercase latin letters
    CHARSET_ALPHA_LOW = (CHARSET_ALPHA_AF_LOW|CHARSET_ALPHA_GZ_LOW),
    /// Uppercase latin letters
    CHARSET_ALPHA_UP = (CHARSET_ALPHA_AF_UP|CHARSET_ALPHA_GZ_UP),
    /// Latin letters of any case
    CHARSET_ALPHA = (CHARSET_ALPHA_LOW|CHARSET_ALPHA_UP),
    /// Alphanumeric: numbers and latin letters of any case
    CHARSET_ALPHANUM = (CHARSET_NUM|CHARSET_ALPHA),
    /// Alphanumeric: numbers and lowercase latin letters
    CHARSET_ALPHANUM_LOW = (CHARSET_NUM|CHARSET_ALPHA_LOW),
    /// Alphanumeric: numbers and uppercase latin letters
    CHARSET_ALPHANUM_UP = (CHARSET_NUM|CHARSET_ALPHA_UP),
} charset_t;

/// Token scan result
typedef struct {
    /// Detected token length
    size_t token_len;
    /// Charset detected, a combination of `charset_t` flags
    uint32_t charset;
    /// Token prefix string, null terminated. Containins up to TOKEN_PREFIX_LEN first
    /// characters of the token.
    char prefix[TOKEN_PREFIX_LEN + 1];
} token_scan_result_t;

// These functions are defined in the main `wallet.c`
extern bool is_lowercase_hex(char c);
extern uint8_t lowercase_hex_to_int(char c);

/**
 * Scans a single token in the buffer while keeping its position.
 *
 * @param[in] buffer
 *   Input buffer with a token to scan, position is preserved.
 * @param[in] separator
 *   A separator character on which scan process is stopped.
 * @param[out] result
 *   Pointer to structure instance receiving scan results.
 *
 * @return true if sucessfull, false in case of error
 */
static bool scan_token(buffer_t *buffer,
                       char separator,
                       token_scan_result_t *result) {
    buffer_snapshot_t in_buf_snapshot = buffer_snapshot(buffer);
    memset(result, 0, sizeof(token_scan_result_t));

    char c;
    while (buffer_peek(buffer, (uint8_t*)&c) && c != separator) {
        if (++result->token_len < sizeof(result->prefix)) {
            result->prefix[result->token_len - 1] = c;
        }

        if (c >= '0' && c <= '9') {
            result->charset |= CHARSET_NUM;
        } else if (c >= 'a' && c <= 'f') {
            result->charset |= CHARSET_ALPHA_AF_LOW;
        } else if (c >= 'g' && c <= 'z') {
            result->charset |= CHARSET_ALPHA_GZ_LOW;
        } else if (c >= 'A' && c <= 'F') {
            result->charset |= CHARSET_ALPHA_AF_UP;
        } else if (c >= 'G' && c <= 'Z') {
            result->charset |= CHARSET_ALPHA_GZ_UP;
        } else if (c == '(' || c == ')') {
            result->charset |= CHARSET_BRACKETS;
        } else {
            result->charset |= CHARSET_OTHER;
        }
        buffer_seek_cur(buffer, 1);
    }

    buffer_restore(buffer, in_buf_snapshot);
    return !!result->token_len;
}

/**
 * Reads lowercase hexadecimal data bytes from buffer.
 *
 * @param[in,out] buffer
 *   Input buffer.
 * @param[out] out
 *   Pointer to output buffer. It is the responsibility of the caller to make sure that the output
 *   buffer is not smaller than the value in variable pointed by `out_len`.
 * @param[in] out_len
 *   Maximum number of bytes to read, must be no greater than INT_MAX.
 * @param[in] terminator
 *   Terminating character used to stop reading input data. Set to -1 if this feature is not needed.
 *
 * @return length of outputted data in bytes or -1 in case of error
 */
static int read_lowercase_hex_data(buffer_t *buffer,
                                   uint8_t *out,
                                   size_t out_len,
                                   int terminator) {
    size_t out_idx = 0;
    uint8_t c;
    char num[2];

    if (out_len > INT_MAX) {
        return -1;
    }

    while (buffer_peek(buffer, &c) && c != terminator && out_idx < out_len) {
        if (!buffer_read_bytes(buffer, (uint8_t *) num, 2)) {
            return -1;
        }
        if (!is_lowercase_hex(num[0]) || !is_lowercase_hex(num[1])) {
            return -1;
        }
        out[out_idx++] = lowercase_hex_to_int(num[0]) << 4 | lowercase_hex_to_int(num[1]);
    }
    return (int)out_idx;
}

/**
 * Prototype for function implementing blinding key parser.
 *
 * This function should parse a BLINDING_KEY expression enclosed in ct() tag as specified in
 * ELIP: 150 and ELIP 151 from the `in_buf` buffer, aallocating the nodes and variables in
 * `out_buf`.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out_buf
 *   Output buffer which receives a tree-like structure of nodes.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
typedef int (*blinding_key_parser_t)(buffer_t *in_buf, buffer_t *out_buf, size_t token_len);

/**
 * Parses slip77() expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out_buf
 *   Output buffer which receives a tree-like structure of nodes.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_slip77(buffer_t *in_buf, buffer_t *out_buf, size_t token_len) {
    UNUSED(token_len);

    policy_node_blinding_privkey_t *node = (policy_node_blinding_privkey_t *)
        buffer_alloc(out_buf, sizeof(policy_node_blinding_privkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->base.type = TOKEN_SLIP77;
    node->base.flags.is_miniscript = 0;

    bool ok = buffer_skip_data(in_buf, (const uint8_t*) "slip77(", sizeof("slip77(") - 1);
    ok = ok && sizeof(node->privkey) ==
            read_lowercase_hex_data(in_buf, node->privkey, sizeof(node->privkey), ')');
    ok = ok && buffer_skip_data(in_buf, (const uint8_t*) ")", 1);

    return ok ? 0 : -1;
}

/**
 * Parses hexadecimal public key expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out_buf
 *   Output buffer which receives a tree-like structure of nodes.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_hex_pubkey(buffer_t *in_buf, buffer_t *out_buf, size_t token_len) {
    UNUSED(token_len);

    policy_node_blinding_pubkey_t *node = (policy_node_blinding_pubkey_t *)
        buffer_alloc(out_buf, sizeof(policy_node_blinding_pubkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->base.type = TOKEN_HEX_PUB;
    node->base.flags.is_miniscript = 0;

    bool ok = sizeof(node->pubkey) ==
        read_lowercase_hex_data(in_buf, node->pubkey, sizeof(node->pubkey), ',');

    return ok && (0x02 == node->pubkey[0] || 0x03 == node->pubkey[0]) ? 0 : -1;
}

/**
 * Parses hexadecimal private key expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out_buf
 *   Output buffer which receives a tree-like structure of nodes.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_hex_privkey(buffer_t *in_buf, buffer_t *out_buf, size_t token_len) {
    UNUSED(token_len);

    policy_node_blinding_privkey_t *node = (policy_node_blinding_privkey_t *)
        buffer_alloc(out_buf, sizeof(policy_node_blinding_privkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->base.type = TOKEN_HEX_PRV;
    node->base.flags.is_miniscript = 0;

    bool ok = sizeof(node->privkey) ==
        read_lowercase_hex_data(in_buf, node->privkey, sizeof(node->privkey), ',');

    return ok ? 0 : -1;
}

/**
 * Parses xpub expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out_buf
 *   Output buffer which receives a tree-like structure of nodes.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_xpub(buffer_t *in_buf, buffer_t *out_buf, size_t token_len) {
    serialized_extended_pubkey_check_t pubkey_check;
    const serialized_extended_pubkey_t *pubkey = &pubkey_check.serialized_extended_pubkey;

    if (!buffer_can_read(in_buf, token_len)) {
        return -1;
    }
    if (sizeof(pubkey_check) != base58_decode((char*) buffer_get_cur(in_buf),
                                              token_len,
                                              (uint8_t *) &pubkey_check,
                                              sizeof(pubkey_check))) {
        return -1;
    }

    uint8_t checksum[4];
    crypto_get_checksum((uint8_t *)&pubkey_check.serialized_extended_pubkey,
                        sizeof(pubkey_check.serialized_extended_pubkey),
                        checksum);
    if (!memeq(checksum, pubkey_check.checksum, sizeof(checksum))) {
        return -1;
    }
    if (read_u32_be(pubkey->version, 0) != BIP32_PUBKEY_VERSION ||
        !(0x02 == pubkey->compressed_pubkey[0] || 0x03 == pubkey->compressed_pubkey[0])) {
        return -1;
    }

    policy_node_blinding_pubkey_t *node = (policy_node_blinding_pubkey_t *)
        buffer_alloc(out_buf, sizeof(policy_node_blinding_pubkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->base.type = TOKEN_XPUB;
    node->base.flags.is_miniscript = 0;
    memcpy(node->pubkey, pubkey->compressed_pubkey, sizeof(node->pubkey));

    return buffer_seek_cur(in_buf, token_len) ? 0 : -1;
}

/**
 * Parses xprv expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out_buf
 *   Output buffer which receives a tree-like structure of nodes.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_xprv(buffer_t *in_buf, buffer_t *out_buf, size_t token_len) {
    serialized_extended_privkey_check_t privkey_check;
    const serialized_extended_privkey_t *privkey = &privkey_check.serialized_extended_privkey;

    if (!buffer_can_read(in_buf, token_len)) {
        return -1;
    }
    if (sizeof(privkey_check) != base58_decode((char*) buffer_get_cur(in_buf),
                                               token_len,
                                               (uint8_t *) &privkey_check,
                                               sizeof(privkey_check))) {
        return -1;
    }

    uint8_t checksum[4];
    crypto_get_checksum((uint8_t *)&privkey_check.serialized_extended_privkey,
                        sizeof(privkey_check.serialized_extended_privkey),
                        checksum);
    if (!memeq(checksum, privkey_check.checksum, sizeof(checksum))) {
        return -1;
    }
    if (read_u32_be(privkey->version, 0) != BIP32_PRIVKEY_VERSION ||
        0 != privkey->null_prefix) {
        return -1;
    }

    policy_node_blinding_privkey_t *node = (policy_node_blinding_privkey_t *)
        buffer_alloc(out_buf, sizeof(policy_node_blinding_privkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->base.type = TOKEN_XPRV;
    node->base.flags.is_miniscript = 0;
    memcpy(node->privkey, privkey->privkey, sizeof(node->privkey));

    return buffer_seek_cur(in_buf, token_len) ? 0 : -1;
}

/**
 * Parses elip151 expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out_buf
 *   Output buffer which receives a tree-like structure of nodes.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_elip151(buffer_t *in_buf, buffer_t *out_buf, size_t token_len) {
    UNUSED(token_len);

    if (!buffer_skip_data(in_buf, (const uint8_t*) "elip151", sizeof("elip151") - 1)) {
        return -1;
    }

    policy_node_t *node = (policy_node_t *)
        buffer_alloc(out_buf, sizeof(policy_node_t), true);

    if (node) {
        node->type = TOKEN_ELIP151;
        node->flags.is_miniscript = 0;
        return 0;
    }
    return -1;
}

/// Blinding key signature
typedef struct {
    size_t min_len;                     ///< Minimum allowed length
    size_t max_len;                     ///< Maximum allowed length
    uint32_t charset;                   ///< Allowed charset
    blinding_key_parser_t parser;       ///< Pinter to a function parsing a BLINDING_KEY expression.
    char prefix[TOKEN_PREFIX_LEN + 1];  ///< Token prefix
} blinding_key_signature_t;

/// Table of known blinding key signatures
static const blinding_key_signature_t BLINDING_KEY_SIGNATURES[] = {
    {
        .prefix = "slip77",
        .min_len = 72,
        .max_len = 72,
        .charset = CHARSET_ALPHANUM_LOW|CHARSET_BRACKETS,
        .parser = parse_ct_slip77
    },
    {
        .prefix = "xpub",
        .min_len = 111,
        .max_len = 112,
        .charset = CHARSET_ALPHANUM,
        .parser = parse_ct_xpub
    },
    {
        .prefix = "xprv",
        .min_len = 111,
        .max_len = 112,
        .charset = CHARSET_ALPHANUM,
        .parser = parse_ct_xprv
    },
    {
        .prefix = "elip151",
        .min_len = 7,
        .max_len = 7,
        .charset = CHARSET_ALPHANUM_LOW,
        .parser = parse_ct_elip151
    },
    {
        .prefix = "",
        .min_len = 64,
        .max_len = 64,
        .charset = CHARSET_HEX_LOW,
        .parser = parse_ct_hex_privkey
    },
    {
        .prefix = "",
        .min_len = 66,
        .max_len = 66,
        .charset = CHARSET_HEX_LOW,
        .parser = parse_ct_hex_pubkey
    }
};
/// Number of records in the table of known blinding key signatures
static const size_t N_BLINDING_KEY_SIGNATURES =
    sizeof(BLINDING_KEY_SIGNATURES) / sizeof(BLINDING_KEY_SIGNATURES[0]);

/**
 * Looks through the table of blinding key signatures and returns corresponding
 * parsing function.
 *
 * @param[in] scan_result
 *   Results of token scan used to find blinding key type by its signature.
 *
 * @return pointer to function parsing identified type of blinding key or NULL if not found.
 */
blinding_key_parser_t find_blinding_key_parser(const token_scan_result_t *scan_result) {
    for (size_t i = 0; i < N_BLINDING_KEY_SIGNATURES; ++i) {
        uint32_t expected_charset = (uint32_t) PIC(BLINDING_KEY_SIGNATURES[i].charset);
        const char *expected_prefix = (const char *) PIC(BLINDING_KEY_SIGNATURES[i].prefix);
        if (0 == (scan_result->charset & ~expected_charset) &&
            scan_result->token_len >= (size_t) PIC(BLINDING_KEY_SIGNATURES[i].min_len) &&
            scan_result->token_len <= (size_t) PIC(BLINDING_KEY_SIGNATURES[i].max_len) &&
            0 == strncmp(expected_prefix,
                         scan_result->prefix,
                         strnlen(expected_prefix, TOKEN_PREFIX_LEN))) {
            return (blinding_key_parser_t) PIC(BLINDING_KEY_SIGNATURES[i].parser);
        }
    }

    return NULL;
}

int liquid_parse_blinding_key_script(buffer_t *in_buf, buffer_t *out_buf) {
    token_scan_result_t scan_result;
    if (!scan_token(in_buf, ',', &scan_result)) {
        return -1;
    }

    blinding_key_parser_t key_parser = find_blinding_key_parser(&scan_result);
    if (key_parser) {
        return (*key_parser)(in_buf, out_buf, scan_result.token_len);
    }
    return -1;
}

bool policy_is_multisig(const policy_node_t *policy) {
    const policy_node_t *node = policy;

    while(node != NULL) {
        switch(node->type)
        {
        case TOKEN_CT:
            node = r_policy_node(&((const policy_node_ct_t *) node)->script);
            break;

        case TOKEN_SH:
        case TOKEN_WSH:
            node = r_policy_node(&((const policy_node_with_script_t *) node)->script);
            break;

        case TOKEN_MULTI:
        case TOKEN_SORTEDMULTI:
            return true;

        // TOKEN_PKH, TOKEN_WPKH, TOKEN_TR
        // TODO: add Taproot multisig when it will be supported project-wise
        default:
            return false;
        }
    }

    return false;
}

// TODO: consider removing
bool validate_policy_map_extended_pubkey(const policy_map_key_info_t *key_info,
                                         uint32_t bip32_pubkey_version) {
    int status = validate_extended_pubkey(
        &key_info->ext_pubkey,
        key_info->master_key_derivation,
        key_info->has_key_origin ? key_info->master_key_derivation_len : -1,
        bip32_pubkey_version
    );

    return EXTENDED_PUBKEY_VALID == status;
}

#endif // HAVE_LIQUID