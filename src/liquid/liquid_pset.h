#pragma once
#ifdef HAVE_LIQUID

#include "../common/buffer.h"
#include "liquid.h"


/// Bits indicating presense (or status) of input's/output's field(s) in PSET
typedef enum {
    /// PSBT_IN_BIP32_DERIVATION or PSBT_IN_TAP_BIP32_DERIVATION
    HAS_BIP32_DERIVATION = (1 << 0),
    /// PSBT_ELEMENTS_OUT_VALUE_COMMITMENT
    HAS_VALUE_COMMITMENT = (1 << 1),
    /// Not used
    HAS_VALUE_BLINDING_FACTOR = (1 << 2),
    /// PSBT_ELEMENTS_IN_EXPLICIT_ASSET or PSBT_ELEMENTS_OUT_ASSET
    HAS_ASSET = (1 << 3),
    /// Not used
    HAS_ASSET_BLINDING_FACTOR = (1 << 4),
    /// PSBT_IN_WITNESS_UTXO
    HAS_WITNESS_UTXO = (1 << 5),
    /// PSBT_IN_NON_WITNESS_UTXO
    HAS_NONWITNESS_UTXO = (1 << 6),
    /// PSBT_IN_REDEEM_SCRIPT
    HAS_REDEEM_SCRIPT = (1 << 7),
    /// PSBT_IN_SIGHASH_TYPE
    HAS_SIGHASH_TYPE = (1 << 8),
    /// Input or output has amount
    HAS_PREVOUT_AMOUNT = (1 << 9),
    /// PSBT_ELEMENTS_OUT_ASSET_COMMITMENT
    HAS_ASSET_COMMITMENT = (1 << 10),
    /// PSBT_ELEMENTS_OUT_BLINDING_PUBKEY
    HAS_BLINDING_PUBKEY = (1 << 11),
    /// PSBT_ELEMENTS_OUT_ECDH_PUBKEY
    HAS_ECDH_PUBKEY = (1 << 12),
    /// PSBT_ELEMENTS_OUT_BLINDER_INDEX
    HAS_BLINDER_INDEX = (1 << 13),
    /// PSBT_ELEMENTS_IN_ISSUANCE_VALUE
    HAS_ISSUANCE_VALUE = (1 << 14),
    /// PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT
    HAS_ISSUANCE_VALUE_COMMITMENT = (1 << 15),
    /// PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE
    HAS_ISSUANCE_BLINDING_NONCE = (1 << 16),
    /// PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY
    HAS_ISSUANCE_ASSET_ENTROPY = (1 << 17),
    /// PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT
    HAS_ISSUANCE_INFLATION_KEYS_COMMITMENT = (1 << 18),
    /// PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT
    HAS_ISSUANCE_INFLATION_KEYS_AMOUNT = (1 << 19),
    /// PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF
    HAS_ISSUANCE_BLIND_VALUE_PROOF = (1 << 20),
    /// PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF
    HAS_ISSUANCE_BLIND_INFLATION_KEYS_PROOF = (1 << 21),
    /// PSBT_ELEMENTS_IN_EXPLICIT_VALUE or PSBT_OUT_AMOUNT
    HAS_VALUE = (1 << 22),
    /// PSBT_ELEMENTS_IN_VALUE_PROOF or PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF
    HAS_VALUE_PROOF = (1 << 23),
    /// PSBT_ELEMENTS_IN_ASSET_PROOF or PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF
    HAS_ASSET_PROOF = (1 << 24),
    /// PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF
    HAS_ASSET_SURJECTION_PROOF = (1 << 25),
    /// PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF
    HAS_VALUE_RANGEPROOF = (1 << 26),
} pset_in_out_key_presence_flags_t;

/// Bits indicating presense (or status) of global field(s) in PSET
typedef enum {
    /// PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA
    GLOBAL_HAS_ASSET_METADATA = (1 << 0),
    /// PSBT_ELEMENTS_HWW_GLOBAL_REISSUANCE_TOKEN
    GLOBAL_HAS_REISSUANCE_TOKEN = (1 << 1)
} pset_global_key_presence_flags_t;

/// A set of flags reflecting transaction type: issuance, reissuance or burn
typedef enum {
    /// Asset issuance is performed in this transaction
    TX_TYPE_ISSUANCE = (1 << 0),
    /// Asset reissuance is performed in this transaction
    TX_TYPE_REISSUANCE = (1 << 1),
    /// Asset burn is performed in this transaction
    TX_TYPE_BURN = (1 << 2)
} pset_transaction_type_flags_t;

/**
 * Tests proprietary key stored in buffer against reference key given as byte array.
 *
 * It is assumed that top-level <keytype> (0xfd) is already taken from the buffer before this
 * function is called and <identifierlen> would be the first value available to read.
 *
 * Buffer position is left unchanged after return.
 *
 * @param[in] buffer
 *   Buffer where proprietary key is stored, without top-level <keytype> (0xfd).
 * @param[in] ref_key
 *   Reference key to test.
 *
 * @return true if key in buffer corresponds to the reference key, false otherwise.
 */
bool pset_test_key(buffer_t *buffer, const uint8_t *ref_key);

/**
 * Convenience function to get the asset tag stored in one of the PSET fields.
 *
 * @param[in,out] dc
 *   Dispatcher context.
 * @param[in] map
 *   Commitment to a merkleized key-value map of this input or output.
 * @param[in] key
 *   Key of a PSET field from which the asset tag needs to be obtained.
 * @param[in] key_len
 *   Length of the key in bytes.
 * @param[out] asset
 *   Pointer to structure instance receiving asset information.
 *
 * @return true on success, false on failure.
 */
bool pset_get_asset_tag(dispatcher_context_t *dc,
                        const merkleized_map_commitment_t *map,
                        const uint8_t *key,
                        int key_len,
                        tx_asset_t *asset);

/**
 * Updates the hash contexts with the network serialization of a single output.
 *
 * @param[in,out] dc
 *   Dispatcher context.
 * @param[in] outputs_root
 *   Merkle root of the vector of output maps commitments.
 * @param[in] n_outputs
 *   Number of outputs in vector.
 * @param[in] output_index
 *   Index of an output to hash.
 * @param[in,out] hash_context
 *   Pre-initialized hash context updated with output's data; may be NULL if unneeded.
 * @param[in,out] rangeproof_hash_context
 *   Pre-initialized hash context updated with output's rangeproof; may be NULL if unneeded.
 *
 * @return 0 on success, -1 on error.
 */
int pset_hash_output(dispatcher_context_t *dc,
                     uint8_t outputs_root[32],
                     unsigned int n_outputs,
                     int output_index,
                     cx_hash_t *hash_context,
                     cx_hash_t *rangeproof_hash_context);

/**
 * Checks whether an input has issuance information.
 *
 * @param[in] key_presence
 *   Bit flags representing presence of PSET keys in current input.
 *
 * @return true if an input has issuance information, otherwise false.
 */
inline bool pset_input_has_issuance(uint32_t key_presence) {
    return !!(key_presence & (HAS_ISSUANCE_VALUE | HAS_ISSUANCE_VALUE_COMMITMENT));
}

/**
 * Updates the hash context with the input's issuance information.
 *
 * @param[in,out] dc
 *   Dispatcher context.
 * @param[in] map
 *   Commitment to a merkleized key-value map of this input.
 * @param[in] key_presence
 *   Bit flags representing presence of PSET keys in current input.
 * @param[in,out] hash_context
 *   Pre-initialized hash context updated with input's data; may be NULL if unneeded.
 *
 * @return true if successfull, false on error.
 */
bool pset_hash_input_issuance(dispatcher_context_t *dc,
                              const merkleized_map_commitment_t *map,
                              uint32_t key_presence,
                              cx_hash_t *hash_context);

/**
 * Returns the text corresponding to transaction type depending of type flags.
 *
 * @param[in] flags
 *   Type flags, a combination of *pset_transaction_type_flags_t* constants.
 *
 * @return  pointer to constant text string or NULL for default transaction type.
 */
const char* pset_get_tx_type_by_flags(uint32_t flags);

/**
 * Detects PSET input key in the buffer.
 *
 * Once a known input key is detected, a corresponding flag is being set in the variable pointed by
 * `p_key_presence`. The function uses values of `pset_in_out_key_presence_flags_t` for flagging the
 * PSET keys.
 *
 * @param[in] data
 *   Data to process containing PSET key. Buffer is not changed after processing.
 * @param[in,out] p_key_presence
 *   Pointer to a variable in which detected key is flagged.
 *
 * @return true on success, false on failure.
 */
void pset_detect_input_key(buffer_t *data, uint32_t *p_key_presence);

/**
 * Detects PSET output key in the buffer.
 *
 * Once a known input key is detected, a corresponding flag is being set in the variable pointed by
 * `p_key_presence`. The function uses values of `pset_in_out_key_presence_flags_t` for flagging the
 * PSET keys.
 *
 * @param[in] data
 *   Data to process containing PSET key. Buffer is not changed after processing.
 * @param[in,out] p_key_presence
 *   Pointer to a variable in which detected key is flagged.
 *
 * @return true on success, false on failure.
 */
void pset_detect_output_key(buffer_t *data, uint32_t *p_key_presence);

#endif // HAVE_LIQUID
