#pragma once
#ifdef HAVE_LIQUID

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include "decorators.h"

#include "../common/wallet.h"

/**
 * The label used to derive the master blinding key according to SLIP-0077
 */
#define SLIP77_LABEL "\0SLIP-0077"
#define SLIP77_LABEL_LEN \
    (sizeof(SLIP77_LABEL) - 1)  // sizeof counts the terminating 0

/**
 * Maximum length of the 'script' field of the LIQUID_GET_BLINDING_KEY command, that is currently
 * supported
 */
#define GET_BLINDING_KEY_MAX_SCRIPT_LEN 252

/**
 * Size of generator in bytes
 */
#define LIQUID_GENERATOR_LEN 65

/**
 * Size of commitment in bytes
 */
#define LIQUID_COMMITMENT_LEN 33

/**
 * Reserved address index used in ELIP 151 for blinding key derivation
 */
#define LIQUID_ELIP151_RESERVED_INDEX ((1UL << 31) - 1)

/**
 * Last valid address index to avoid conflict with ELIP 151 blinding key derivation
 */
#define LIQUID_LAST_ADDRESS_INDEX (LIQUID_ELIP151_RESERVED_INDEX - 1)

/**
 * Compression trait of a public key
 */
typedef enum {
    LIQUID_PUBKEY_UNCOMPRESSED = 0, // Public key is compressed, 33 bytes
    LIQUID_PUBKEY_COMPRESSED = 1    // Public key is uncompressed, 65 bytes
} liquid_pubkey_compression_t;

typedef struct {
    uint32_t p2pkh_version;
    uint32_t p2sh_version;
    uint32_t prefix_confidential;
    char segwit_prefix[MAX_SEGWIT_PREFIX_LENGTH+1];
    char segwit_prefix_confidential[MAX_SEGWIT_PREFIX_LENGTH+1];
} liquid_network_config_t;

#if defined(HAVE_LIQUID) && !defined(SKIP_FOR_CMOCKA)
// Network configuration defined at build time from Makefile variables
extern const liquid_network_config_t G_liquid_network_config;
#endif

/**
 * Callback function obtaining `scriptPubKey` of the processed descriptor.
 *
 * If `p_key_wildcard_to_verify` is not NULL, the function assumes it points to a constant which
 * must be compared with each of the wallet's public key's wildcard identifier. This parameter is
 * optional. If wildcard verification is not required it should be set to NULL.
 *
 * @param[in,out] state
 *   Callback state, stores necessary properties of the processed descriptor.
 * @param[in] bip44_change
 *   Change element of the derivation path, defined according to BIP 44.
 * @param[in] bip44_address_index
 *   Address index element of the derivation path, defined according to BIP 44.
 * @param[out] out_buffer
 *   Buffer receiving `scriptPubKey`.
 * @param[in] p_key_wildcard_to_verify
 *   If not NULL, requests to verify all wallet's public key wildcard IDs to be equal to value, pointed
 *   by this parameter.
 *
 * @return true if successful, false if error.
 */
typedef bool (*liquid_get_script_callback_t)(
    void *state,
    uint32_t bip44_change,
    uint32_t bip44_address_index,
    buffer_t *out_buffer,
    const policy_map_key_wildcard_id_t *p_key_wildcard_to_verify
);

/**
 * Derives master blinding key from seed according to SLIP-0077.
 *
 * @param[out] mbk
 *   Pointer to a 32-byte output buffer that will contain the generated key.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT bool liquid_get_master_blinding_key(uint8_t mbk[static 32]);

/**
 * Derives blinding key from given script.
 *
 * @param[in] mbk
 *   Pointer to master blinding key.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] blinding_key
 *   Pointer to a 32-byte output buffer that will contain the generated key.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT bool liquid_get_blinding_key(const uint8_t mbk[static 32],
                                                const uint8_t *script,
                                                size_t script_length,
                                                uint8_t blinding_key[static 32]);

/**
 * Returns a prefix for confidential SegWit address from a given SegWit address prefix.
 *
 * @param[in] segwit_prefix
 *   SegWit address prefix used for look-up.
 *
 * @return Prefix for a confidential SegWit address or NULL if unsuccessfull.
 */
const char* liquid_confidential_segwit_prefix(const char* segwit_prefix);

/**
 * Returns a confidential address from given script and public key.
 *
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[in] network_config
 *   Network configuration.
 * @param[out] pubkey
 *   Public key.
 * @param[out] p_pubkey_len
 *   Length of the public key in bytes: 33 or 65.
 * @param[out] out
 *   Output buffer where produced address is placed.
 * @param[in] out_len
 *   Maximum length to write for the output buffer.
 *
 * @return size of produced address in bytes, or -1 in case of error.
 */
WARN_UNUSED_RESULT int liquid_get_script_confidential_address(const uint8_t *script,
                                                              size_t script_len,
                                                              const liquid_network_config_t *network_config,
                                                              const uint8_t *pub_key,
                                                              size_t pub_key_len,
                                                              char *out,
                                                              size_t out_len);

/**
 * Unwraps ct() tag from wallet policy.
 *
 * @param[in] policy
 *   Pointer to root policy node.
 *
 * @return pointer to policy node inside ct() tag, or to the root node if the policy is not blinded.
 */
static inline const policy_node_t* liquid_policy_unwrap_ct(const policy_node_t *policy) {
    return policy && (TOKEN_CT == policy->type) ? ((const policy_node_ct_t*)policy)->script : policy;
}

/**
 * Derives blinding public key from the given policy with `ct` descriptor.
 *
 * @param[in] policy
 *   Pointer to a root policy node whose outer descriptor must be `ct` and contain blinding key.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[in] pubkey_wildcard_id
 *   Identifier of public key wildcard, one of `policy_map_key_wildcard_id_t` values. Needed only
 *   for ELIP 151.
 * @param[in] get_script_callback
 *   Callback function obtaining `scriptPubKey` of the processed descriptor. Needed only for
 *   ELIP 151.
 * @param[in,out] get_script_callback_state
 *   State of `get_script_callback`, a user-defined value passed to callback function. Needed only
 *   for ELIP 151.
 * @param[out] pubkey
 *   Buffer receiving derived public key, must be not smaller than 33 bytes.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool liquid_get_blinding_public_key(const policy_node_t *policy,
                                                       const uint8_t *script,
                                                       size_t script_length,
                                                       policy_map_key_wildcard_id_t pubkey_wildcard_id,
                                                       liquid_get_script_callback_t get_script_callback,
                                                       void *get_script_callback_state,
                                                       uint8_t pubkey[static 33]);

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
 *   Buffer receiving derived public blinding key, must be at least 33 bytes long.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool liquid_derive_blinding_public_key_elip150(const uint8_t bare_pubkey[static 33],
                                                                  const uint8_t *script,
                                                                  size_t script_length,
                                                                  uint8_t out_pubkey[static 33]);

/**
 * Validates the blinding key in the policy ensuring that it can be accepted.
 *
 * For SLIP-0077 derivation, this function also checks if the master blinding key is ours.
 *
 * @param[in] policy
 *   Pointer to a root policy node whose outer descriptor must be `ct` and contain blinding key.
 *
 * @return true if the policy having this specific blinding key is acceptable, false otherwise.
 */
bool liquid_is_blinding_key_acceptable(const policy_node_t *policy);

/**
 * Verifies if the given master blinding key is ours.
 *
 * @param[in] mbk
 *   Master blinding key to test, exactly 32 bytes.
 *
 * @return true if the given master blinding key is ours, false otherwise
 */
bool liquid_is_master_blinding_key_ours(const uint8_t mbk[static 32]);

/**
 * Checks if policy corresponds to a blinded wallet.
 *
 * @param[in] policy
 *   Pointer to a root policy node.
 *
 * @return true if wallet is blinded, false otherwise.
 */
static inline bool liquid_policy_is_blinded(const policy_node_t *policy) {
    return policy && (TOKEN_CT == policy->type);
}

#endif // HAVE_LIQUID
