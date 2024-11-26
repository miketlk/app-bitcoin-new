#pragma once
#ifdef HAVE_LIQUID

#include <stdint.h>
#include <stdbool.h>
#ifndef SKIP_FOR_CMOCKA
#include "../boilerplate/dispatcher.h"
#include "merkle.h"
#endif
#include "liquid_assets.h"
#include "contract_parser.h"

/// Status of asset metadata
typedef enum {
    /// Asset metadata is ready
    ASSET_METADATA_READY = 0,
    /// Asset metadata is ready for a corresponding reissuance token
    ASSET_METADATA_TOKEN_READY = 1,
    /// Asset metadata is absent in PSET for the given asset tag
    ASSET_METADATA_ABSENT = -1,
    /// An error occurred while retreiving asset metadata or the metadata is invalid
    ASSET_METADATA_ERROR = -2,
    /// Merkle tree leaf specified by index has a wrong key
    ASSET_METADATA_WRONG_KEY = -3
} asset_metadata_status_t;

/// Contex of asset metadata parser
typedef struct {
    /// State of the parser's FSM
    int state;
    /// Context of contract parser
    contract_parser_context_t contract_parser_ctx;
    /// Size of the contract
    uint32_t contract_len;
    /// Prevout transaction hash
    uint8_t prevout_txid[SHA256_LEN];
    /// Zero-based index of the transaction output
    uint32_t prevout_index;
    /// Index of a byte that is currently read
    size_t read_idx;
    /// Number of bytes remaining to read
    size_t read_remaining;
} asset_metadata_parser_context_t;

#ifndef SKIP_FOR_CMOCKA

/**
 * Reads and verifies asset metadata from a PSET map for the given asset tag.
 *
 * If parameter *ext_asset_info* is non-NULL, the parameter *asset_info* must point to the same
 * memory address or be NULL.
 *
 * If the parameter *search_reissuance_token* is true, it permits the function to search for a
 * reissuance token with a given tag when the asset is not found. In this case, the function returns
 * `ASSET_METADATA_TOKEN_READY` instead of `ASSET_METADATA_READY` as a successful status code.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context used for I/O operations with host.
 * @param[in] global_map
 *   Commitment to merkleized key-value map of global PSET fields.
 * @param[in] asset_tag
 *   Asset tag used to search for metadata.
 * @param[in] search_reissuance_token
 *   If true, tries to find a reissuance token with the given tag if the asset is not found.
 * @param[out] asset_info
 *   Poiter to output asset information structure, may be NULL if *ext_asset_info* is provided.
 * @param[out] ext_asset_info
 *   Poiter to output extended asset information structure, may be NULL if not needed.
 *
 * @return status of asset metadata.
 *
 * NOTE: this function does _not_ check that the keys are lexicographically sorted; the sanity check
 * needs to be done before.
 */
WARN_UNUSED_RESULT asset_metadata_status_t
liquid_get_asset_metadata(dispatcher_context_t *dispatcher_context,
                          const merkleized_map_commitment_t *global_map,
                          const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
                          bool search_reissuance_token,
                          asset_info_t *asset_info,
                          asset_info_ext_t *ext_asset_info);

/**
 * Reads and verifies asset metadata from a PSET map from the given Merkle tree leaf.
 *
 * This function returns ASSET_METADATA_WRONG_KEY if the key stored in Merkle tree leaf doesn't
 * correspond to PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA.
 *
 * If parameter *ext_asset_info* is non-NULL, the parameter *asset_info* must point to the same
 * memory address or be NULL.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context used for I/O operations with host.
 * @param[in] global_map
 *   Commitment to merkleized key-value map of global PSET fields.
 * @param[in] leaf_index
 *   Leaf index.
 * @param[out] asset_tag
 *   Buffer receiving asset tag retrieved from keydata.
 * @param[out] asset_info
 *   Poiter to output asset information structure, may be NULL if *ext_asset_info* is provided.
 * @param[out] ext_asset_info
 *   Poiter to output extended asset information structure, may be NULL if not needed.
 *
 * @return status of asset metadata.
 *
 * NOTE: this function does _not_ check that the keys are lexicographically sorted; the sanity check
 * needs to be done before.
 */
WARN_UNUSED_RESULT asset_metadata_status_t
liquid_get_asset_metadata_by_leaf_index(dispatcher_context_t *dispatcher_context,
                                        const merkleized_map_commitment_t *global_map,
                                        uint32_t leaf_index,
                                        uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
                                        asset_info_t *asset_info,
                                        asset_info_ext_t *ext_asset_info);

#endif  // SKIP_FOR_CMOCKA
#endif  // HAVE_LIQUID
