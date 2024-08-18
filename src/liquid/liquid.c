#ifdef HAVE_LIQUID

#include <stdint.h>
#include <string.h>
#include "crypto.h"
#include "liquid.h"
#include "liquid_addr.h"
#include "../common/script.h"
#include "../handler/lib/policy.h"
#include "tests.h"

#ifdef SKIP_FOR_CMOCKA
// disable problematic macros when compiling unit tests with CMOCKA
#define PIC(x) (x)
#endif // SKIP_FOR_CMOCKA

/// RIPEMD160 message digest size
#define HASH160_LEN 20

#ifndef SKIP_FOR_CMOCKA

/// Network configuration defined at build time from Makefile variables
const liquid_network_config_t G_liquid_network_config =  {
    .p2pkh_version = COIN_P2PKH_VERSION,
    .p2sh_version = COIN_P2SH_VERSION,
    .prefix_confidential = COIN_PREFIX_CONFIDENTIAL,
    .segwit_prefix = COIN_NATIVE_SEGWIT_PREFIX,
    .segwit_prefix_confidential = COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL
};

// ELIP 150 tag for computing the hashed tag function used for tweaking public keys
static const uint8_t ELIP150_hash_tag[] =
    {'C', 'T', '-', 'B', 'l', 'i', 'n', 'd', 'i', 'n', 'g', '-', 'K', 'e', 'y', '/', '1', '.', '0'};

// ELIP 151 tag for computing the hashed tag function used for private blinding key derivation
static const uint8_t ELIP151_hash_tag[] =
    {'D', 'e', 't', 'e', 'r', 'm', 'i', 'n', 'i', 's', 't', 'i', 'c', '-', 'V', 'i', 'e', 'w', '-',
     'K', 'e', 'y', '/', '1', '.', '0'};

bool liquid_get_master_blinding_key(uint8_t mbk[static 32]) {
    return crypto_derive_symmetric_key(SLIP77_LABEL, SLIP77_LABEL_LEN, mbk);
}

bool liquid_is_master_blinding_key_ours(const uint8_t mbk[static 32]) {
    uint8_t ours_mbk[32];

    bool ok = liquid_get_master_blinding_key(ours_mbk);
    ok = ok && 0 == os_secure_memcmp((void *) mbk, (void *) ours_mbk, sizeof(ours_mbk));

    explicit_bzero(ours_mbk, sizeof(ours_mbk));
    return ok;
}

bool liquid_get_blinding_key(const uint8_t mbk[static 32],
                             const uint8_t *script,
                             size_t script_length,
                             uint8_t blinding_key[static 32]) {
    cx_hmac_sha256_t hmac;
    return ( CX_OK == cx_hmac_sha256_init_no_throw(&hmac, mbk, 32) &&
             CX_OK == cx_hmac_no_throw( (cx_hmac_t*)&hmac,
                                        CX_LAST,
                                        script,
                                        script_length,
                                        blinding_key,
                                        32) );
}



/**
 * Derives blinding public key from given bare public key according to ELIP 150.
 *
 * @param[in] bare_pubkey
 *   Bare compressed public blinding key, 33 bytes.
 * @param[in] script
 *   Script `scriptPubKey` used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] out_pubkey
 *   Buffer receiving derived public blinding key, must be at least 33 bytes long. Can be the same
 *   as `bare_pubkey` for in-place processing.
 *
 * @return true on success, false in case of error.
 */
static bool __attribute__((noinline)) elip150_derive_public_key(
    const uint8_t bare_pubkey[static 33],
    const uint8_t *script,
    size_t script_length,
    uint8_t out_pubkey[static 33]) {
    if(!bare_pubkey || !script || !out_pubkey ||
       !(0x02 == bare_pubkey[0] || 0x03 == bare_pubkey[0])) {
        return false;
    }

    bool ok = true;
    uint8_t hash_bytes[SHA256_LEN];
    {
        // Calculate tagget hash
        cx_sha256_t hash_context;
        crypto_tr_tagged_hash_init(&hash_context, ELIP150_hash_tag, sizeof(ELIP150_hash_tag));
        crypto_hash_update(&hash_context.header, bare_pubkey, 33);
        crypto_hash_update_varint(&hash_context.header, script_length);
        crypto_hash_update(&hash_context.header, script, script_length);
        crypto_hash_digest(&hash_context.header, hash_bytes, sizeof(hash_bytes));
        explicit_bzero(&hash_context, sizeof(hash_context));
    }

    cx_ecfp_public_key_t tweak_pubkey_inst;
    {
        cx_ecfp_private_key_t tweak_privkey_inst;

        // New private key instance from 256-bit hash scalar
        ok = ok && CX_OK == cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                                              hash_bytes,
                                                              sizeof(hash_bytes),
                                                              &tweak_privkey_inst);

        // Generate corresponding public key (tweak point)
        ok = ok && CX_OK == cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1,
                                                           &tweak_pubkey_inst,
                                                           &tweak_privkey_inst,
                                                           1);

        explicit_bzero(&tweak_privkey_inst, sizeof(tweak_privkey_inst));
    }

    {
        uint8_t point[65];

        // Uncompress bare public key
        ok = ok && 0 == crypto_get_uncompressed_pubkey(bare_pubkey, point);
        // Add tweak point
        ok = ok && CX_OK == cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1,
                                                       point,
                                                       point,
                                                       tweak_pubkey_inst.W);
        // Compress and output resulting public key
        if (ok) {
            out_pubkey[0] = ((point[64] & 1) ? 0x03 : 0x02);
            memcpy(out_pubkey + 1, point + 1, 32);
        }
        explicit_bzero(point, sizeof(point));
    }

    explicit_bzero(hash_bytes, sizeof(hash_bytes));
    explicit_bzero(&tweak_pubkey_inst, sizeof(tweak_pubkey_inst));

    return ok;
}

/**
 * Derives blinding private key according to ELIP 151.
 *
 * @param[in] n_descriptors
 *   Number single descriptors in the multipath scheme. Only 1 and 2 are supported.
 * @param[in] get_script_callback
 *   Callback function obtaining `scriptPubKey` of the processed descriptor.
 * @param[in,out] get_script_callback_state
 *   State of `get_script_callback`, a user-defined value passed to callback function.
 * @param[out] out_privkey
 *   Buffer receiving derived private blinding key, must be at least 32 bytes long.
 *
 * @return true on success, false in case of error.
 */
static bool __attribute__((noinline)) elip151_derive_private_key(
    uint32_t n_descriptors,
    liquid_get_script_callback_t get_script_callback,
    void *get_script_callback_state,
    uint8_t out_privkey[static 32]) {
    if(!get_script_callback || !out_privkey || !n_descriptors) {
        return false;
    }

    // Prepare tagged hash context with tag `Deterministic-View-Key/1.0`
    cx_sha256_t hash_context;
    crypto_tr_tagged_hash_init(&hash_context, ELIP151_hash_tag, sizeof(ELIP151_hash_tag));

    // Expand multi-path to every single descriptor and process each
    // `scriptPubKey` at index 2^31-1.
    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    for(uint32_t descriptor_idx = 0; descriptor_idx < n_descriptors; ++descriptor_idx) {
        // Obtain scriptPubKey at index 2^31-1
        buffer_t script_buffer = buffer_create(script, sizeof(script));
        bool res = ((liquid_get_script_callback_t) PIC(get_script_callback))(
            get_script_callback_state,
            descriptor_idx,
            LIQUID_ELIP151_RESERVED_INDEX,
            &script_buffer
        );
        if (!res) {
            return false;
        }
        // Hash scriptPubKey prepended with OP_INVALIDOPCODE
        crypto_hash_update_u8(&hash_context.header, 1); // Length of OP_INVALIDOPCODE
        crypto_hash_update_u8(&hash_context.header, OP_INVALIDOPCODE);
        crypto_hash_update_varint(&hash_context.header, buffer_stored(&script_buffer));
        crypto_hash_update(&hash_context.header, script, buffer_stored(&script_buffer));
    }

    crypto_hash_digest(&hash_context.header, out_privkey, 32);

    explicit_bzero(&hash_context, sizeof(&hash_context));
    explicit_bzero(script, sizeof(script));

    return true;
}

/**
 * Prototype for function deriving public blinding key from policy node and script.
 *
 * @param[in] policy
 *   Pointer to a specific policy node containing blinding key or derivation tag.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] pubkey
 *   Buffer receiving derived public key, must be not smaller than 33 bytes.
 *
 * @return true if successful, false if error.
 */
typedef bool (*pubkey_derivator_proto_t)(const policy_node_t *blinding_key_node,
                                         const uint8_t *script,
                                         size_t script_length,
                                         uint8_t pubkey[static 33]);

/// Record in a table of functions deriving public blinding key.
typedef struct {
    /// Type of policy node.
    int32_t type;
    /// Function deriving public blinding key from policy node and script.
    pubkey_derivator_proto_t derivator;
} pubkey_derivator_t;

/**
 * Derives public blinding key from `slip77` policy node and script.
 *
 * @param[in] policy
 *   Pointer to `slip77` policy node containing blinding key or derivation tag.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] pubkey
 *   Buffer receiving derived public key, must be not smaller than 33 bytes.
 *
 * @return true if successful, false if error.
 */
static bool derive_pubkey_slip77(const policy_node_t *blinding_key_node,
                                 const uint8_t *script,
                                 size_t script_length,
                                 uint8_t pubkey[static 33]) {
    if (TOKEN_SLIP77 != blinding_key_node->type) {
        return false;
    }
    const policy_node_blinding_privkey_t *slip77 =
        (const policy_node_blinding_privkey_t*) blinding_key_node;

    uint8_t raw_privkey[32];

    // Get raw blinding key
    bool ok = liquid_get_blinding_key(slip77->privkey, script, script_length, raw_privkey);
    // Derive corresponding public key
    ok = ok && crypto_generate_compressed_pubkey_pair(raw_privkey, pubkey);

    // Zeroize sensitive data
    explicit_bzero(&raw_privkey, sizeof(raw_privkey));

    return ok;
}


/**
 * Derives public blinding key from a bare public key according to ELIP 150.
 *
 * @param[in] policy
 *   Pointer to `slip77` policy node containing blinding key or derivation tag.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] pubkey
 *   Buffer receiving derived public key, must be not smaller than 33 bytes.
 *
 * @return true if successful, false if error.
 */
static bool derive_pubkey_elip150_from_bare_pubkey(const policy_node_t *blinding_key_node,
                                                   const uint8_t *script,
                                                   size_t script_length,
                                                   uint8_t pubkey[static 33]) {
    if (TOKEN_HEX_PUB != blinding_key_node->type &&
        TOKEN_XPUB != blinding_key_node->type) {
        return false;
    }
    const policy_node_blinding_pubkey_t *node_pubkey =
        (const policy_node_blinding_pubkey_t*) blinding_key_node;

    return elip150_derive_public_key(node_pubkey->pubkey, script, script_length, pubkey);
}

/**
 * Derives public blinding key from a bare private key according to ELIP 150.
 *
 * @param[in] policy
 *   Pointer to `slip77` policy node containing blinding key or derivation tag.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] pubkey
 *   Buffer receiving derived public key, must be not smaller than 33 bytes.
 *
 * @return true if successful, false if error.
 */
static bool derive_pubkey_elip150_from_bare_privkey(const policy_node_t *blinding_key_node,
                                                    const uint8_t *script,
                                                    size_t script_length,
                                                    uint8_t pubkey[static 33]) {
    if (TOKEN_HEX_PRV != blinding_key_node->type &&
        TOKEN_XPRV != blinding_key_node->type) {
        return false;
    }
    const policy_node_blinding_privkey_t *node_privkey =
        (const policy_node_blinding_privkey_t*) blinding_key_node;

    bool ok = crypto_generate_compressed_pubkey_pair(node_privkey->privkey, pubkey);
    ok = ok && elip150_derive_public_key(pubkey, script, script_length, pubkey);

    return ok;
}

/// Table of functions deriving public blinding key.
static const pubkey_derivator_t PUBKEY_DERIVATORS[] = {
    { .type = TOKEN_SLIP77,  .derivator = derive_pubkey_slip77 },
    { .type = TOKEN_HEX_PUB, .derivator = derive_pubkey_elip150_from_bare_pubkey },
    { .type = TOKEN_HEX_PRV, .derivator = derive_pubkey_elip150_from_bare_privkey },
    { .type = TOKEN_XPUB,    .derivator = derive_pubkey_elip150_from_bare_pubkey },
    { .type = TOKEN_XPRV,    .derivator = derive_pubkey_elip150_from_bare_privkey }
};

/// Number of records in the table of known blinding key signatures
static const size_t N_PUBKEY_DERIVATORS =
    sizeof(PUBKEY_DERIVATORS) / sizeof(PUBKEY_DERIVATORS[0]);

/**
 * Finds the appropriate function deriving public blinding for the given policy node type.
 *
 * Returned value is a pointer function corresponding to `pubkey_derivator_proto_t` type.
 *
 * @param[in] node_type
 *   Type of policy node.
 *
 * @return pointer to derivation function if sucessfull or NULL if not found.
 */
static pubkey_derivator_proto_t find_pubkey_derivator(PolicyNodeType node_type) {
    for (size_t i = 0; i < N_PUBKEY_DERIVATORS; ++i) {
        if ((int32_t) PIC(PUBKEY_DERIVATORS[i].type) == node_type) {
            return (pubkey_derivator_proto_t) PIC(PUBKEY_DERIVATORS[i].derivator);
        }
    }
    return NULL;
}

/**
 * Derives public blinding key according to ELIP 151.
 *
 * @param[in] n_descriptors
 *   Number single descriptors in the multipath scheme. Only 1 and 2 are supported.
 * @param[in] get_script_callback
 *   Callback function obtaining `scriptPubKey` of the processed descriptor.
 * @param[in,out] get_script_callback_state
 *   State of `get_script_callback`, a user-defined value passed to callback function.
 * @param[out] pubkey
 *   Buffer receiving derived public key, must be not smaller than 33 bytes.
 *
 * @return true if successful, false if error.
 */
static bool get_blinding_public_key_elip151(const uint8_t *script,
                                            size_t script_length,
                                            uint32_t n_descriptors,
                                            liquid_get_script_callback_t get_script_callback,
                                            void *get_script_callback_state,
                                            uint8_t pubkey[static 33]) {
    uint8_t privkey[32];

    bool ok = elip151_derive_private_key(n_descriptors,
                                         get_script_callback,
                                         get_script_callback_state,
                                         privkey);
    ok = ok && crypto_generate_compressed_pubkey_pair(privkey, pubkey);
    ok = ok && elip150_derive_public_key(pubkey, script, script_length, pubkey);

    explicit_bzero(privkey, sizeof(privkey));
    return ok;
}

/**
 * Returns the number of possible single descriptors in the multipath scheme of the policy.
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 *
 * @return the number of possible descriptors or -1 in case of error.
 */
static int get_descriptor_number(const policy_node_t *policy) {
    if (!policy) {
        return -1;
    }

    int n_descriptors = -1;
    int n_placeholders, i = 0;

    do {
        policy_node_key_placeholder_t placeholder;
        n_placeholders = get_key_placeholder_by_index(policy, i, NULL, &placeholder);
        if (n_placeholders < 1) {
            // No public keys in policy
            return -1;
        }

        if (policy_is_key_placeholder_empty(&placeholder) ||
            placeholder.num_first >= BIP32_FIRST_HARDENED_CHILD ||
            placeholder.num_second >= BIP32_FIRST_HARDENED_CHILD) {
            // Expected <M;N> key placeholder with unhardened M and N
            return -1;
        }

        int n_curr = placeholder.num_first == placeholder.num_second ? 1 : 2;
        if (n_descriptors != -1 && n_curr != n_descriptors) {
            // Mismatch in descriptor number among different public keys
            return -1;
        }
        n_descriptors = n_curr;
    } while(++i < n_placeholders);

    return n_descriptors;
}

bool liquid_get_blinding_public_key(const policy_node_t *policy,
                                    const uint8_t *script,
                                    size_t script_length,
                                    liquid_get_script_callback_t get_script_callback,
                                    void *get_script_callback_state,
                                    uint8_t pubkey[static 33]) {
    if(!policy || TOKEN_CT != policy->type || !script || !pubkey) {
        return false;
    }

    const policy_node_t *mbk_script =
        r_policy_node(&((const policy_node_ct_t *) policy)->mbk_script);
    if (!mbk_script) {
        return false;
    }

    if (TOKEN_ELIP151 == mbk_script->type) {
        int n_descriptors =
            get_descriptor_number(r_policy_node(&((const policy_node_ct_t *) policy)->script));
        if(n_descriptors < 1) {
            return false;
        }
        return get_blinding_public_key_elip151(script,
                                               script_length,
                                               n_descriptors,
                                               get_script_callback,
                                               get_script_callback_state,
                                               pubkey);
    } else {
        pubkey_derivator_proto_t derivator = find_pubkey_derivator(mbk_script->type);
        return NULL == derivator ?
            false : (*derivator)(mbk_script, script, script_length, pubkey);
    }
}

bool liquid_is_blinding_key_acceptable(const policy_node_t *policy) {
    if(!policy || policy->type != TOKEN_CT) {
        return false;
    }

    const policy_node_t *mbk_script =
        r_policy_node(&((const policy_node_ct_t *) policy)->mbk_script);
    if(mbk_script) {
        // Ensure we have an appropriate derivation function for this kind of key
        if (NULL == find_pubkey_derivator(mbk_script->type)) {
            return false;
        }

        // For SLIP-0077 derivation verify that the master key is ours, except for the multisig
        // descriptors
        if (TOKEN_SLIP77 == mbk_script->type && !policy_is_multisig(policy)) {
            const policy_node_blinding_privkey_t *slip77 =
                (const policy_node_blinding_privkey_t *)mbk_script;
            if (!liquid_is_master_blinding_key_ours(slip77->privkey)) {
                return false;
            }
        }

        return true;
    }
    return false;
}

#endif // !SKIP_FOR_CMOCKA

int liquid_get_script_confidential_address(const uint8_t *script,
                                           size_t script_len,
                                           const liquid_network_config_t *network_config,
                                           const uint8_t *pub_key,
                                           size_t pub_key_len,
                                           char *out,
                                           size_t out_len) {
    if(!script || !network_config ||!pub_key || !out) {
        return -1;
    }

    int script_type = get_script_type(script, script_len);
    if(script_type < 0 || script_len < 4) {
        return -1; // invalid script
    }

    int addr_len = -1;
    switch (script_type) {
        case SCRIPT_TYPE_P2PKH:
        case SCRIPT_TYPE_P2SH: {
            int offset = (script_type == SCRIPT_TYPE_P2PKH) ? 3 : 2;
            int ver = (script_type == SCRIPT_TYPE_P2PKH) ? network_config->p2pkh_version
                                                         : network_config->p2sh_version;
            if(script_len - offset < HASH160_LEN) {
                return -1;
            }
            addr_len = liquid_encode_address_base58(script + offset,
                                                    HASH160_LEN,
                                                    network_config->prefix_confidential,
                                                    ver,
                                                    pub_key,
                                                    pub_key_len,
                                                    out,
                                                    out_len);
            break;
        }
        case SCRIPT_TYPE_P2WPKH:
        case SCRIPT_TYPE_P2WSH:
        case SCRIPT_TYPE_P2TR:
        case SCRIPT_TYPE_UNKNOWN_SEGWIT: {
            uint8_t prog_len = script[1];  // length of the witness program
            int version = (script[0] == 0 ? 0 : script[0] - 80); // witness program version
            if(prog_len > script_len - 2) {
                return -1;
            }
            addr_len = liquid_encode_address_segwit(script + 2,
                                                    prog_len,
                                                    network_config->segwit_prefix_confidential,
                                                    version,
                                                    pub_key,
                                                    pub_key_len,
                                                    out,
                                                    out_len);
            break;
        }
    }
    return addr_len;
}

#ifdef IMPLEMENT_ON_DEVICE_TESTS
#include "liquid_tests.h"
#endif

#endif // HAVE_LIQUID
