#pragma once

#ifdef HAVE_LIQUID

#include "cx.h"
#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../constants.h"

#ifndef RAWTX_DECODE_ECDH_PUBKEY
#define RAWTX_DECODE_ECDH_PUBKEY 0
#endif

/// Confidential or non-confidential amount
typedef struct {
    /// If true, the value is blinded and stored as commitment[], otherwise as value
    bool is_blinded;
    union {
        /// Normal value of the output
        uint64_t value;
        /// Amount commitment of a confidential output
        uint8_t commitment[33];
    };
} tx_amount_t;

/// Confidential or non-confidential asset
typedef struct {
    /// If true the asset is blinded and stored as commitment[], otherwise as tag
    bool is_blinded;
    union {
        /// Explicit asset tag in "display" byte order
        uint8_t tag[32];
        /// Asset commitment of a confidential output
        uint8_t commitment[33];
    };
} tx_asset_t;

/// Information on transaction output
typedef struct {
    /// Confidential or non-confidential asset
    tx_asset_t asset;
    /// Confidential or non-confidential amount
    tx_amount_t amount;
#if RAWTX_DECODE_ECDH_PUBKEY
    /// ECDH public key of the output
    uint8_t ecdh_pubkey[33];
    /// If true, the ECDH public key is valid
    bool ecdh_pubkey_valid;
#endif
    /// Length of the scriptPubKey
    unsigned int scriptpubkey_len;
    /// Output's scriptpubkey, a locking script
    uint8_t scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];  // will contain the scriptPubKey
} txid_parser_vout_t;

/// Data outputted by transaction parser
typedef struct {
    /// Will contain the information of the requested output
    txid_parser_vout_t vout;
    /// Will contain the computed txid, transaction identifier
    uint8_t txid[32];
} txid_parser_outputs_t;


/**
 * Parses a serialized Elements transaction while computing issuance hash
 *
 * Given a commitment to a merkleized map and a key, this flow parses it as a serialized Elements
 * transaction, computes the transaction ID and optionally saves parameters of one of its outputs.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context used for I/O operations with host.
 * @param[in] map
 *   Commitment to merkleized key-value map of PSET input.
 * @param[in] key
 *   Key of PSET field containing a transaction to parse.
 * @param[in] key_len
 *   Length of the key in bytes.
 * @param[in] output_index
 *   Index of an output to retrieve, or -1 if not needed.
 * @param[out] outputs
 *   Pointer to structure instance receiving parser outputs.
 * @param[in,out] issuance_hash_context
 *   Pointer to a pre-initialized SHA-256 context used to compute issuance hash, NULL if not needed.
 *
 * @return 0 if success, a negative number on failure.
 */
int call_psbt_parse_rawtx_ex(dispatcher_context_t *dispatcher_context,
                             const merkleized_map_commitment_t *map,
                             const uint8_t *key,
                             int key_len,
                             int output_index,
                             txid_parser_outputs_t *outputs,
                             cx_sha256_t *issuance_hash_context);

/**
 * Parses a serialized Elements transaction
 *
 * Given a commitment to a merkleized map and a key, this flow parses it as a serialized Elements
 * transaction, computes the transaction ID and optionally saves parameters of one of its outputs.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context used for I/O operations with host.
 * @param[in] map
 *   Commitment to merkleized key-value map of PSET input.
 * @param[in] key
 *   Key of PSET field containing a transaction to parse.
 * @param[in] key_len
 *   Length of the key in bytes.
 * @param[in] output_index
 *   Index of an output to retrieve, or -1 if not needed.
 * @param[out] outputs
 *   Pointer to structure instance receiving parser outputs.
 *
 * @return 0 if success, a negative number on failure.
 */
static inline int __attribute__((always_inline))
call_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context,
                      const merkleized_map_commitment_t *map,
                      const uint8_t *key,
                      int key_len,
                      int output_index,
                      txid_parser_outputs_t *outputs) {
    return call_psbt_parse_rawtx_ex(dispatcher_context,
                                    map,
                                    key,
                                    key_len,
                                    output_index,
                                    outputs,
                                    NULL);
}

/**
 * Parses a single output of a serialized Elements transaction
 *
 * Given a commitment to a merkleized map and a key, this flow parses it as a single output of
 * a serialized Elements transaction (typically UTXO) and saves results into provided structure.
 * Hashing is optional and disabled if 'hash_context' argument is NULL.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context used for I/O operations with host.
 * @param[in] map
 *   Commitment to merkleized key-value map of PSET input.
 * @param[in] key
 *   Key of PSET field containing a transaction to parse.
 * @param[in] key_len
 *   Length of the key in bytes.
 * @param output
 *   Pointer to structure instance receiving parser outputs.
 * @param hash_context
 *   Pointer to a pre-initialized SHA-256 context used to compute output hash, NULL if not needed.
 *
 * @return 0 if success, a negative number on failure.
 */
int call_psbt_parse_rawtx_single_output(dispatcher_context_t *dispatcher_context,
                                        const merkleized_map_commitment_t *map,
                                        const uint8_t *key,
                                        int key_len,
                                        txid_parser_vout_t *output,
                                        cx_sha256_t *hash_context);

#endif // HAVE_LIQUID
