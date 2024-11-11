#pragma once

#ifdef HAVE_LIQUID

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "decorators.h"
#include "constants.h"
#include "buffer.h"
#include "liquid_assets.h"
#include "liquid_hash_wrappers.h"

/// Maximum reasonable length of the contract
#define CONTRACT_MAX_LEN (10 * 1024)
/// Maximum length of key field in JSON (not including quotes and terminating null)
#define CONTRACT_MAX_KEY_LEN 9
/// Maximum length of value field in JSON (not including quotes and terminating null)
#define CONTRACT_MAX_VALUE_LEN 31
/// Maximum nesting level for objects, 0 - no nested objects allowed
#define CONTRACT_MAX_NESTING_LEVEL 1

/// Nested keys
typedef struct {
    /// Array of nested keys, lower index corresponds to top level keys
    char k[CONTRACT_MAX_NESTING_LEVEL + 1][CONTRACT_MAX_KEY_LEN + 1];
} contract_parser_nested_keys_t;

/// Contract parser context
typedef struct {
    /// Pointer to structure receiving output values
    asset_info_t *asset_info;
    /// Flags indicating presence of the contract fields
    uint32_t field_presence_flags;
    /// State of the parser's FSM
    int state;
    /// Flag: current chunk has opening quotes
    bool has_opening_quotes;
    /// Flag: this character was escaped by '\'
    bool escape;
    /// Current zero-based level for nested objects and arrays
    uint32_t nesting_level;
    /// Current zero-based level for skipped nested objects and arrays
    uint32_t skip_nesting_level;
    /// Key buffer
    contract_parser_nested_keys_t key;
    /// Length of the key w/o trailing null character
    int key_len;
    /// Value buffer of a key-value pair
    char value[CONTRACT_MAX_VALUE_LEN + 1];
    /// Length of the value w/o trailing null character
    int value_len;
    /// Context of SHA-256 used to compute contreact hash
    cx_sha256_t sha256_context;
    /// If nonzero parser outputs extended asset information
    uint8_t parse_ext_info;
} contract_parser_context_t;

/**
 * Initializes contract parser.
 *
 * If parameter *ext_asset_info* is non-NULL, the parameter *asset_info* must point to the same
 * memory address or be NULL.
 *
 * @param[out] ctx
 *   Instance of parser context to initialize.
 * @param[out] asset_info
 *   Poiter to output asset information structure, may be NULL if *ext_asset_info* is provided.
 * @param[out] ext_asset_info
 *   Poiter to output extended asset information structure, may be NULL if not needed.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool contract_parser_init(contract_parser_context_t *ctx,
                                             asset_info_t *asset_info,
                                             asset_info_ext_t *ext_asset_info);

/**
 * Processes input contract data.
 *
 * @param[out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Input data buffer to process.
 *
 * @return true on success, false in case of error.
 */
void contract_parser_process(contract_parser_context_t *ctx, buffer_t *data);

/**
 * Finalizes contract processing.
 *
 * Call this function to obtain output values after feeding all bytes of a contract to
 * contract_parser_process().
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[out] hash
 *   Pointer to buffer receiving computed contract hash.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool contract_parser_finalize(contract_parser_context_t *ctx,
                                                 uint8_t hash[static SHA256_LEN]);

#endif  // HAVE_LIQUID
