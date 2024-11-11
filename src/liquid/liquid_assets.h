#pragma once
#ifdef HAVE_LIQUID

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "decorators.h"
#include "../constants.h"
#include "ledger_assert.h"

/// Ticker for unknown asset
#define UNKNOWN_ASSET_TICKER "???"
/// Number of decimal digits in fractional part of an unknown asset
#define UNKNOWN_ASSET_DECIMALS 0
/// Size of asset tag in bytes
#define LIQUID_ASSET_TAG_LEN SHA256_LEN
/// Size of a hexadecimal asset tag in bytes
#define LIQUID_ASSET_TAG_HEX_LEN (LIQUID_ASSET_TAG_LEN * 2)
/// Minimum value of decimals
#define LIQUID_ASSET_DECIMALS_MIN 0
/// Maximum value of decimals
#define LIQUID_ASSET_DECIMALS_MAX 19
/// Maximum length of asset name
#define MAX_ASSET_NAME_LENGTH 31
/// Maximum length of asset domain
#define MAX_ASSET_DOMAIN_LENGTH 31

// Asset class, denoting ordinary assets, and reissuance tokens
typedef enum {
    /// Ordinary asset issued on the Liquid Network
    ACLASS_ASSET = 0,
    /// Reissuance token, non-confidential
    ACLASS_REISSUANCE_TOKEN_NON_CONFIDENTIAL = 1,
    /// Reissuance token, confidential
    ACLASS_REISSUANCE_TOKEN_CONFIDENTIAL = 2
} asset_class_t;

/// Information about an asset
typedef struct {
    /// Ticker, a text string
    char ticker[MAX_ASSET_TICKER_LENGTH + 1];
    /// Number of decimal digits in fractional part
    uint8_t decimals;
} asset_info_t;

/// Extended information about an asset, may be casted to asset_info_t
typedef struct {
    /// Basic information about an asset
    asset_info_t info;
    /// Asset name, a text string
    char name[MAX_ASSET_NAME_LENGTH + 1];
    /// Asset domain, a text string
    char domain[MAX_ASSET_DOMAIN_LENGTH + 1];
} asset_info_ext_t;

/// Definition of an asset
typedef struct {
    /// Asset tag
    uint8_t tag[LIQUID_ASSET_TAG_LEN];
    /// Information about an asset
    asset_info_t info;
} asset_definition_t;

/// Asset cache, holding tags of confirmed assets
typedef struct {
    /// Pointer to cache buffer containing asset tags
    uint8_t *buffer;
    /// Cache capacity: number of tags it's capable to store
    uint8_t capacity;
    /// Number of assets in cache
    uint8_t asset_n;
    /// Write index in cache
    uint8_t write_idx;
} asset_cache_t;

/// Asset tag of L-BTC or TL-BTC depending on build
extern const uint8_t liquid_bitcoin_tag[LIQUID_ASSET_TAG_LEN];

/**
 * Finds information about asset
 *
 * @param[in] tag asset tag for look-up
 *
 * @return pointer to asset definition structure or NULL if not found
 */
const asset_info_t *liquid_get_asset_info(const uint8_t tag[static LIQUID_ASSET_TAG_LEN]);

/**
 * Checks wether the given asset tag corresponds to L-BTC (or TL-BTC for tentnet build)
 *
 * @param[in] tag asset tag for look-up
 * @return true
 * @return false
 */
static inline bool liquid_is_asset_bitcoin(const uint8_t tag[static LIQUID_ASSET_TAG_LEN]) {
    return 0 == memcmp(tag, liquid_bitcoin_tag, sizeof(liquid_bitcoin_tag));
}

/**
 * Computes asset tag (asset ID).
 *
 * Contract hash should be single SHA-256 hash of canonicalized contract JSON with reverse byte
 * order (like in TXID).
 *
 * @param[in] contract_hash
 *   Ricardian contract hash, 32 bytes, SHA-256 with reverse byte order.
 * @param[in] prevout_txid
 *   Prevout transaction hash, 32 bytes.
 * @param[in] prevout_index
 *   Zero-based index of the transaction output.
 * @param[in] asset_class
 *   Asset class, one of *asset_class_t* constants.
 * @param[out] asset_tag
 *   Pointer to a 32-byte output buffer receiving computed asset tag.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool liquid_compute_asset_tag(const uint8_t contract_hash[static SHA256_LEN],
                                                 const uint8_t prevout_txid[static SHA256_LEN],
                                                 uint32_t prevout_index,
                                                 asset_class_t asset_class,
                                                 uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]);

/**
 * Converts an asset tag to a hexadecimal string
 *
 * @param[in] asset_tag
 *   A 32-byte asset tag.
 * @param[out] out
 *   Pointer to a 65-byte output buffer receiving hexadecimal representation of asset tag.
 */
void liquid_format_asset_tag(const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
                             char out[static LIQUID_ASSET_TAG_HEX_LEN + 1]);

/**
 * Creates an asset cache using pre-allocated storage buffer.
 *
 * @param[in,out]  ptr
 *   Pointer to the buffer's data.
 * @param[in]  size
 *   Size of the buffer in bytes.
 *
 * @return descriptor structure of the newly created cache.
 */
static inline asset_cache_t asset_cache_create(void *ptr, size_t size) {
    _Static_assert(LIQUID_ASSET_TAG_LEN == (1 << 5), "Unsupported asset tag size");
    LEDGER_ASSERT((size >> 5) > 0 && (size >> 5) <= UINT8_MAX, "Invalid size of asset cache");

    return (asset_cache_t) {.buffer = (uint8_t *) ptr,
                            .capacity = (size >> 5),
                            .asset_n = 0,
                            .write_idx = 0};
}

/**
 * Puts asset in cache.
 *
 * This function does nothing if the parameter `cache` is NULL. Built-in assets
 * are ignored.
 *
 * @param[in] cache
 *   Instance of the cache structure, allowed to be NULL.
 * @param[in] asset_tag
 *   Asset tag to put intop cache.
 */
void asset_cache_put(asset_cache_t *cache, const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]);

/**
 * Searches through cached assets for a given asset tag.
 *
 * This function always return false if the parameter `cache` is NULL. Built-in
 * assets are assumed "always in cache" and the function returns true if a
 * tag of built-in asset is passed.
 *
 * @param[in] cache
 *   Instance of the cache structure, allowed to be NULL.
 * @param[in] asset_tag
 *   Asset tag to search for.
 *
 * @return true if asset is found or built-in asset, false otherwise.
 */
bool asset_cache_find(const asset_cache_t *cache,
                      const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]);

#endif  // HAVE_LIQUID
