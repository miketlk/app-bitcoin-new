#pragma once

#ifdef HAVE_LIQUID_WIP

#include "../boilerplate/dispatcher.h"
#include "../constants.h"
#include "../common/bitvector.h"
#include "../common/merkle.h"
#include "../common/wallet.h"
#include "../liquid/liquid.h"
#include "../liquid/liquid_assets.h"

/// Maximum supported number of transaction inputs
#define MAX_N_INPUTS_CAN_SIGN 512
/// Size of memory pool where SHA-256 contexts are allocated (number of units)
#define SIGN_PSET_SHA_CONTEXT_POOL_SIZE 3
/// Size of cache holding asset tags of confirmed assets
#define ASSET_CACHE_SIZE 1
/// Maximum supported number of transaction outputs
#define MAX_N_OUTPUTS (UINT32_MAX - 1)
/// A constant used for `fee_output_index` to indicate that fee index is unknown
#define SIGN_PSET_FEE_INDEX_UNKNOWN UINT32_MAX

#if ASSET_CACHE_SIZE > 254
#error Requested size of asset cache is not supported
#endif

// Paranoid checks to make sure we can use uint8_t instead of bool to save memory
#if (true < 0) || (true > UINT8_MAX) || (false < 0) || (false > UINT8_MAX)
    #error Boolean constant is incompatible with uint8_t
#endif

/// Common information that applies to either an input or an output
typedef struct {
    /// Commitment to a merkleized key-value map of this input or output
    merkleized_map_commitment_t map;

    /// The pubkey of the first PSBT_{IN,OUT}_BIP32_DERIVATION or PSBT_{IN,OUT}_TAP_BIP32_DERIVATION
    /// key seen. Could be 33 (legacy or segwitv0) or 32 bytes long (taproot), based on the script
    /// type.
    uint8_t bip32_derivation_pubkey[33];

    /// For an output, this is its scriptPubKey. For an input, it's the prevout's scriptPubKey
    /// (either from the non-witness-utxo, or from the witness-utxo).
    uint8_t scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    /// Length of the data stored in scriptPubKey[]
    size_t scriptPubKey_len;

    /// Value or amount
    uint64_t value;
    /// Value commitment
    uint8_t value_commitment[LIQUID_COMMITMENT_LEN];
    /// Asset commitment
    uint8_t asset_commitment[LIQUID_COMMITMENT_LEN];
    /// Asset tag
    uint8_t asset_tag[LIQUID_ASSET_TAG_LEN];
    /// Information about the asset: ticher and precision
    asset_info_t asset_info;
    /// If true the asset is defined in internal asset list
    uint8_t built_in_asset;
    /// If true the asset is a reissuance token
    uint8_t asset_is_reissuance_token;
} in_out_info_t;

/// Information specific to input
typedef struct {
    /// The script used when signing, either from the witness utxo or the redeem script
    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    /// Length of the script
    size_t script_len;

    /// SIGHASH type, a combination of flags
    uint32_t sighash_type;
    /// Change deviation index in BIP32 path
    int change;
    /// Address index (last deviation index in BIP32 path)
    int address_index;
} input_info_t;

/// Information specific to output
typedef struct {
} output_info_t;

/// Overlaid structure representing one input or output
typedef struct  {
    /// Common information that applies to either the current input or the current output
    in_out_info_t in_out;
    union {
        /// Information specific to the current input
        input_info_t input;
        /// Information specific to the current output
        output_info_t output;
    };

    /// Bit flags representing presence in transaction of PSET keys in current input/output.
    /// A combination of key_presence_flags_t bits.
    uint32_t key_presence;
    /// Bit flags representing status of PSET fields: the ones which were read are set.
    /// A combination of key_presence_flags_t bits.
    uint32_t key_read_status;
} overlayed_in_out_info_t;

/// Asset cache, holding tags of confirmed assets
typedef struct {
    /// Cache buffer containing asset tags
    uint8_t asset_tags[ASSET_CACHE_SIZE][LIQUID_ASSET_TAG_LEN];
    /// Number of assets in cache
    uint8_t asset_n;
    /// Write index in cache
    uint8_t write_idx;
} asset_cache_t;

/// State of SIGN_PSBT command in Liquid application
typedef struct {
    /// Machine context for command dispatcher
    machine_context_t ctx;

    /// Global transaction version
    uint32_t tx_version;
    /// Global fallback locktime
    uint32_t locktime;

    /// Number of transaction inputs
    uint32_t n_inputs;
    /// Merkle root of the vector of input maps commitments
    uint8_t inputs_root[32];
    /// Number of outputs
    uint32_t n_outputs;
    /// Merkle root of the vector of output maps commitments
    uint8_t outputs_root[32];

    /// If true the wallet is canonical
    uint8_t is_wallet_canonical;
    /// BIP 44 "purpose" deviation index, only relevant for canonical wallets
    int bip44_purpose;

    /// Merkle root of the vector of key descriptors
    uint8_t wallet_header_keys_info_merkle_root[32];
    /// Number of keys in wallet policy
    size_t wallet_header_n_keys;

    /// Master key fingerprint
    uint32_t master_key_fingerprint;

    /// Bitmap to track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];

    // Shared index variables
    union {
        /// Input index
        unsigned int cur_input_index;
        /// Output index
        unsigned int cur_output_index;
        /// Allocator's index of SHA-256 conexts
        unsigned int sha_context_index;
        /// Global key index
        unsigned int cur_global_key_index;
    };

    // Shared memory area for input/output information and SHA-256 contexts
    union {
        /// Overlaid structure representing one input or output
        overlayed_in_out_info_t cur;
        /// Pool of SHA256 contexts used in compute_segwit_hashes()
        cx_sha256_t sha_context_pool[SIGN_PSET_SHA_CONTEXT_POOL_SIZE];
    };

    /// Computed sighash value
    uint8_t sighash[32];

    // Shared memory area for wallet policy and SegWit hash values
    union {
        union {
            /// Wallet policy as an array of bytes
            uint8_t map_bytes[MAX_POLICY_MAP_BYTES];
            /// Parsed wallet policy
            policy_node_t map;
        } wallet_policy;
        struct {
            /// SHA256 of the serialization of all input outpoints
            uint8_t sha_prevouts[SHA256_LEN];
            /// SHA256 of the serialization of all input amounts or amount commitments
            uint8_t sha_amounts[SHA256_LEN];
            /// SHA256 of the serialization of all input scriptPubKey
            uint8_t sha_scriptpubkeys[SHA256_LEN];
            /// SHA256 of the serialization of nSequence of all inputs
            uint8_t sha_sequences[SHA256_LEN];
            /// SHA256 of the serialization of all output amount
            uint8_t sha_outputs[SHA256_LEN];
            /// SHA256 of the serialization of all input issuance information
            uint8_t sha_issuances[SHA256_LEN];
            /// SHA256 of the serialization of all output rangeproofs
            uint8_t sha_rangeproofs[SHA256_LEN];
        } hashes;
    };
    /// Pinter to "unwrapped" wallet policy with removed blinding key
    const policy_node_t *wallet_policy_map_unwrapped;
    /// Root type of wallet policy
    PolicyNodeType wallet_policy_root_type;

    /// Total value of all inputs
    uint64_t inputs_total_value;
    /// Total value of all outputs
    uint64_t outputs_total_value;
#ifdef LIQUID_HAS_SWAP
    /// Total value of all change outputs
    uint64_t change_outputs_total_value;
#endif
    /// Value of fee output
    uint64_t fee_value;
    /// Index of fee input
    uint32_t fee_output_index;

    /// Count of external outputs that are shown to the user
    int external_outputs_count;
    /// Count of outputs compatible with change outputs
    int change_count;

    /// Derivation path of "our" key used to sign transaction
    uint32_t our_key_derivation[MAX_BIP32_PATH_STEPS];
    /// Length of the derivation path stored in our_key_derivation[]
    int our_key_derivation_length;

    /// Bit flags representing presence in transaction of global PSET keys.
    /// A combination of key_presence_flags_t bits.
    uint32_t global_key_presence;
    /// Commitment to a merkleized key-value map of global fields
    merkleized_map_commitment_t global_map;

    /// Asset cache, holding tags of confirmed assets
    asset_cache_t asset_cache;

    /// A set of flags reflecting transaction type: issuance, reissuance or burn
    uint8_t tx_type_flags;
} sign_pset_state_t;

/**
 * Handles SIGN_PSBT command in Liquid application.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context.
 */
void handler_liquid_sign_pset(dispatcher_context_t *dispatcher_context);

#endif // HAVE_LIQUID
