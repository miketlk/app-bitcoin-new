#pragma once
#ifdef HAVE_LIQUID

#include "../common/wallet.h"

// TODO: remove
#ifdef HAVE_LIQUID
/// Maximum supported number of keys for a policy map.
#define MAX_POLICY_MAP_COSIGNERS 7
#else
/// Maximum supported number of keys for a policy map.
#define MAX_POLICY_MAP_COSIGNERS 5
#endif


// TODO: replace with MAX_PUBKEYS_PER_MULTISIG
/// Maximum supported number of keys for a policy map.
#define MAX_POLICY_MAP_KEYS MAX_POLICY_MAP_COSIGNERS

// TODO: consider removing
/// Public key wildcards defining the rules for child key derivation.
typedef enum {
    /// No wildcard.
    KEY_WILDCARD_NONE = 0,
    /// Any derivation is allowed: `/**`.
    KEY_WILDCARD_ANY = 1,
    /// Internal or external chain with an arbitrary address index: `/<0;1>/*`.
    KEY_WILDCARD_STANDARD_CHAINS,
    /// External chain with an arbitrary address index: `/0/*`.
    KEY_WILDCARD_EXTERNAL_CHAIN,
    /// Internal chain (change) with an arbitrary address index: `/1/*`.
    KEY_WILDCARD_INTERNAL_CHAIN,
} policy_map_key_wildcard_id_t;

// TODO: remove
/// Policy node ct()
typedef struct {
    /// Type of this policy node is TOKEN_MULTI or TOKEN_SORTEDMULTI
    struct policy_node_s base;
    /// Master blinding key script, typically slip77()
    rptr_policy_node_t mbk_script;
    /// Inner script
    rptr_policy_node_t script;
} policy_node_ct_t;

/// Policy node containing ELIP 150 blinding public key
typedef struct {
    /// Type of this policy node is TOKEN_HEX_PUB, TOKEN_XPUB
    struct policy_node_s base;
    /// Compressed public key
    uint8_t pubkey[33];
} policy_node_blinding_pubkey_t;

/// Policy node containing ELIP 150 blinding private key
typedef struct {
    /// Type of this policy node is TOKEN_SLIP77, TOKEN_HEX_PRV, TOKEN_XPRV
    struct policy_node_s base;
    /// Private key
    uint8_t privkey[32];
} policy_node_blinding_privkey_t;

/**
 * Checks if the policy specifies a multisignature wallet.
 *
 * @param[in] policy
 *   Pointer to wallet's top-level policy node.
 *
 * @return true if the wallet is multisig, false otherwise.
 */
bool policy_is_multisig(const policy_node_t *policy);

/**
 * Validates the public key stored in key information for a policy map wallet.
 *
 * @param[in] key_info
 *   Key information.
 * @param bip32_pubkey_version
 *   Version prefix to use for the public key.
 *
 * @return true if key is valid, false otherwise.
 */
bool validate_policy_map_extended_pubkey(const policy_map_key_info_t *key_info,
                                         uint32_t bip32_pubkey_version);

#endif // HAVE_LIQUID