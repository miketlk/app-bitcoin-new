#ifdef HAVE_LIQUID

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "../util.h"
#include "liquid.h"
#include "liquid_hash_wrappers.h"
#include "liquid_assets.h"
#include "tests.h"

#ifdef SKIP_FOR_CMOCKA
#define STATIC_NO_TEST
#else
/// Declares symbol as static in non-test build
#define STATIC_NO_TEST static
#endif

/// Asset list, sorted by tag
STATIC_NO_TEST const asset_definition_t liquid_assets[] = {
    {{0x0e, 0x99, 0xc1, 0xa6, 0xda, 0x37, 0x9d, 0x1f, 0x41, 0x51, 0xfb,
      0x9d, 0xf9, 0x04, 0x49, 0xd4, 0x0d, 0x06, 0x08, 0xf6, 0xcb, 0x33,
      0xa5, 0xbc, 0xbf, 0xc8, 0xc2, 0x65, 0xf4, 0x2b, 0xab, 0x0a},
     {"LCAD", 8}},
    {{0x34, 0x38, 0xec, 0xb4, 0x9f, 0xc4, 0x5c, 0x08, 0xe6, 0x87, 0xde,
      0x47, 0x49, 0xed, 0x62, 0x8c, 0x51, 0x1e, 0x32, 0x64, 0x60, 0xea,
      0x43, 0x36, 0x79, 0x4e, 0x1c, 0xf0, 0x27, 0x41, 0x32, 0x9e},
     {"JPYS", 0}},
    {{0x5a, 0xc9, 0xf6, 0x5c, 0x0e, 0xfc, 0xc4, 0x77, 0x5e, 0x0b, 0xae,
      0xc4, 0xec, 0x03, 0xab, 0xdd, 0xe2, 0x24, 0x73, 0xcd, 0x3c, 0xf3,
      0x3c, 0x04, 0x19, 0xca, 0x29, 0x0e, 0x07, 0x51, 0xb2, 0x25},
     {"TL-BTC", 8}},
    {{0x6f, 0x02, 0x79, 0xe9, 0xed, 0x04, 0x1c, 0x3d, 0x71, 0x0a, 0x9f,
      0x57, 0xd0, 0xc0, 0x29, 0x28, 0x41, 0x64, 0x60, 0xc4, 0xb7, 0x22,
      0xae, 0x34, 0x57, 0xa1, 0x1e, 0xec, 0x38, 0x1c, 0x52, 0x6d},
     {"L-BTC", 8}},
    {{0xb0, 0x0b, 0x0f, 0xf0, 0xb1, 0x1e, 0xbd, 0x47, 0xf7, 0xc6, 0xf5,
      0x76, 0x14, 0xc0, 0x46, 0xdb, 0xbd, 0x20, 0x4e, 0x84, 0xbf, 0x01,
      0x17, 0x8b, 0xaf, 0x2b, 0xe3, 0x71, 0x3a, 0x20, 0x6e, 0xb7},
     {"BTSE", 8}},
    {{0xb2, 0xe1, 0x5d, 0x0d, 0x7a, 0x0c, 0x94, 0xe4, 0xe2, 0xce, 0x0f,
      0xe6, 0xe8, 0x69, 0x1b, 0x9e, 0x45, 0x13, 0x77, 0xf6, 0xe4, 0x6e,
      0x80, 0x45, 0xa8, 0x6f, 0x7c, 0x4b, 0x5d, 0x4f, 0x0f, 0x23},
     {"RL-BTC", 8}},
    {{0xce, 0x09, 0x1c, 0x99, 0x8b, 0x83, 0xc7, 0x8b, 0xb7, 0x1a, 0x63,
      0x23, 0x13, 0xba, 0x37, 0x60, 0xf1, 0x76, 0x3d, 0x9c, 0xfc, 0xff,
      0xae, 0x02, 0x25, 0x8f, 0xfa, 0x98, 0x65, 0xa3, 0x7b, 0xd2},
     {"USDt", 8}},
    {{0xd9, 0xf6, 0xbb, 0x51, 0x6c, 0x9f, 0x3a, 0xb1, 0x6b, 0xed, 0x3f,
      0x36, 0x62, 0xae, 0x01, 0x85, 0x73, 0xee, 0x6b, 0x00, 0x13, 0x0f,
      0x23, 0x47, 0xa4, 0xb7, 0x35, 0xd8, 0xe7, 0xc4, 0xc3, 0x96},
     {"SAI", 8}},
    {{0xf5, 0x9c, 0x5f, 0x3e, 0x81, 0x41, 0xf3, 0x22, 0x27, 0x6d, 0xaa,
      0x63, 0xed, 0x5f, 0x30, 0x70, 0x85, 0x80, 0x8a, 0xea, 0x6d, 0x4e,
      0xf9, 0xba, 0x61, 0xe2, 0x81, 0x54, 0x53, 0x3f, 0xde, 0xc7},
     {"AUDL", 2}},
    {{0xff, 0xff, 0x7e, 0x44, 0x8a, 0x09, 0x97, 0x7d, 0xbb, 0x2d, 0x32,
      0x20, 0x91, 0x54, 0xfc, 0x4f, 0xb4, 0x4f, 0x1e, 0x10, 0x98, 0xd8,
      0x05, 0x74, 0xf6, 0x6c, 0x3a, 0x8e, 0x0a, 0xb5, 0x55, 0x9f},
     {"BEER", 8}},
};

/// Number of assets in list
#define N_LIQUID_ASSETS (sizeof(liquid_assets) / sizeof(liquid_assets[0]))

/// Asset tag of L-BTC or TL-BTC depending on build
const uint8_t liquid_bitcoin_tag[LIQUID_ASSET_TAG_LEN] = {
#ifdef HAVE_LIQUID_TEST
    /// Asset tag of TL-BTC
    0x5a, 0xc9, 0xf6, 0x5c, 0x0e, 0xfc, 0xc4, 0x77, 0x5e, 0x0b, 0xae,
    0xc4, 0xec, 0x03, 0xab, 0xdd, 0xe2, 0x24, 0x73, 0xcd, 0x3c, 0xf3,
    0x3c, 0x04, 0x19, 0xca, 0x29, 0x0e, 0x07, 0x51, 0xb2, 0x25
#else
    /// Asset tag of L-BTC
    0x6f, 0x02, 0x79, 0xe9, 0xed, 0x04, 0x1c, 0x3d, 0x71, 0x0a, 0x9f,
    0x57, 0xd0, 0xc0, 0x29, 0x28, 0x41, 0x64, 0x60, 0xc4, 0xb7, 0x22,
    0xae, 0x34, 0x57, 0xa1, 0x1e, 0xec, 0x38, 0x1c, 0x52, 0x6d
#endif
};

#ifdef SKIP_FOR_CMOCKA
/// Constant storing number of assets in list
const size_t n_liquid_assets = N_LIQUID_ASSETS;
#endif

const asset_info_t *liquid_get_asset_info(const uint8_t tag[static LIQUID_ASSET_TAG_LEN]) {
    _Static_assert(N_LIQUID_ASSETS > 1, "Asset list should contain at least 2 entries");

    if (!tag) {
        return NULL;
    }

    size_t low = 0;
    size_t high = N_LIQUID_ASSETS - 1;
    size_t mid;
    int cmp;

    // Make binary search
    while (low <= high) {
        mid = (low + high) >> 1;
        cmp = memcmp(liquid_assets[mid].tag, tag, sizeof(liquid_assets[0].tag));
        if (cmp < 0) {
            low = mid + 1;
        } else if (cmp > 0) {
            if (mid) {
                high = mid - 1;
            } else {
                return NULL;
            }
        } else {
            return &liquid_assets[mid].info;
        }
    }
    return NULL;
}

#ifndef SKIP_FOR_CMOCKA

/**
 * Retrieves SHA-256 midstate from hash context with byte reversing.
 *
 * @param[in] sha256_context
 *   The context of SHA-256 from which midstate should be retrieved.
 * @param[out] out
 *   Pointer to a 32-byte output buffer receiving byte-reversed SHA-256 midstate.
 *
 * @return true on success, false in case of error.
 */
static bool sha256_midstate_reversed(const cx_sha256_t *sha256_context,
                                     uint8_t out[static SHA256_LEN]) {
    if (sha256_context && CX_SHA256 == sha256_context->header.info->md_type) {
        uint8_t *p_out = &out[SHA256_LEN - 1];
        for (int i = 0; i < SHA256_LEN; i += 4) {
            for (int j = 3; j >= 0; --j) {
                *p_out-- = sha256_context->acc[i + j];
            }
        }
        return true;
    }
    return false;
}

#else   // SKIP_FOR_CMOCKA

extern bool sha256_midstate_reversed(const cx_sha256_t *sha256_context,
                                     uint8_t out[static SHA256_LEN]);
#endif  // SKIP_FOR_CMOCKA

/**
 * Generate the asset entropy from the issuance prevout and the contract hash.
 *
 * @param[in] contract_hash
 *   Ricardian contract hash, 32 bytes.
 * @param[in] prevout_txid
 *   Prevout transaction hash, 32 bytes.
 * @param[in] prevout_index
 *   Zero-based index of the transaction output.
 * @param[out] entropy
 *   Pointer to a 32-byte output buffer receiving computed asset entropy.
 *
 * @return true on success, false in case of error.
 */
STATIC_NO_TEST bool generate_asset_entropy(const uint8_t contract_hash[static SHA256_LEN],
                                           const uint8_t prevout_txid[static SHA256_LEN],
                                           uint32_t prevout_index,
                                           uint8_t entropy[static SHA256_LEN]) {
    cx_sha256_t sha_ctx;
    uint8_t hash[SHA256_LEN];

    // Compute h1 = SHA256(prevout_txid || prevout_index.le)
    bool ok = hash_init_sha256(&sha_ctx) &&
              hash_update_reversed(&sha_ctx.header, prevout_txid, SHA256_LEN) &&
              hash_update_u32_le(&sha_ctx.header, prevout_index) &&
              hash_digest(&sha_ctx.header, hash, sizeof(hash));

    // Compute h2 = SHA256(h1)
    ok = ok && hash_init_sha256(&sha_ctx) && hash_update(&sha_ctx.header, hash, sizeof(hash)) &&
         hash_digest(&sha_ctx.header, hash, sizeof(hash));

    // Compute E = SHA256(h2 || contract_hash).midstate
    ok = ok && hash_init_sha256(&sha_ctx) && hash_update(&sha_ctx.header, hash, sizeof(hash)) &&
         hash_update_reversed(&sha_ctx.header, contract_hash, SHA256_LEN) &&
         sha256_midstate_reversed(&sha_ctx, entropy);

    return ok;
}

/**
 * Computes asset tag from asset entropy
 *
 * @param[in] entropy
 *   Asset entropy, 32 bytes.
 * @param[in] asset_class
 *   Asset class, one of *asset_class_t* constants.
 * @param[out] asset_tag
 *   Pointer to a 32-byte output buffer receiving computed asset tag.
 *
 * @return true on success, false in case of error.
 */
STATIC_NO_TEST bool compute_asset_tag_from_entropy(const uint8_t entropy[SHA256_LEN],
                                                   asset_class_t asset_class,
                                                   uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]) {
    _Static_assert(LIQUID_ASSET_TAG_LEN == SHA256_LEN, "Wrong tag size");

    cx_sha256_t sha_ctx;

    bool ok = hash_init_sha256(&sha_ctx) &&
              hash_update_reversed(&sha_ctx.header, entropy, SHA256_LEN) &&
              hash_update_u8(&sha_ctx.header, (uint8_t) asset_class);

    for (int i = 0; i < SHA256_LEN - 1; ++i) {
        ok = ok && hash_update_u8(&sha_ctx.header, 0);
    }

    return ok && sha256_midstate_reversed(&sha_ctx, asset_tag);
}

bool liquid_compute_asset_tag(const uint8_t contract_hash[static SHA256_LEN],
                              const uint8_t prevout_txid[static SHA256_LEN],
                              uint32_t prevout_index,
                              asset_class_t asset_class,
                              uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]) {
    if (!contract_hash || !prevout_txid || !asset_tag) {
        return false;
    }

    uint8_t entropy[SHA256_LEN];
    bool ok = generate_asset_entropy(contract_hash, prevout_txid, prevout_index, entropy);
    ok = ok && compute_asset_tag_from_entropy(entropy, asset_class, asset_tag);

    return ok;
}

void liquid_format_asset_tag(const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
                             char out[static LIQUID_ASSET_TAG_HEX_LEN + 1]) {
    for (int i = 0; i < LIQUID_ASSET_TAG_LEN; ++i) {
        snprintf(out + 2 * i, 3, "%02X", asset_tag[i]);
    }
}

void asset_cache_put(asset_cache_t *cache, const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]) {
    if (!cache || !asset_tag || !cache->buffer || !cache->capacity) {
        return;
    }

    if (NULL != liquid_get_asset_info(asset_tag)) {
        // We don't put built-in assets in cache
        return;
    }

    if (!asset_cache_find(cache, asset_tag)) {
        memcpy(cache->buffer + (size_t) cache->write_idx * LIQUID_ASSET_TAG_LEN,
               asset_tag,
               LIQUID_ASSET_TAG_LEN);

        if (++cache->write_idx >= cache->capacity) {
            cache->write_idx = 0;
        }
        if (++cache->asset_n > cache->capacity) {
            cache->asset_n = cache->capacity;
        }
    }
}

bool asset_cache_find(const asset_cache_t *cache,
                      const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]) {
    if (!cache || !asset_tag || !cache->buffer || !cache->capacity) {
        return false;
    }

    if (NULL != liquid_get_asset_info(asset_tag)) {
        // Assume built-in assets are always in cache
        return true;
    }

    for (size_t offset = 0; offset < (size_t) cache->asset_n * LIQUID_ASSET_TAG_LEN;
         offset += LIQUID_ASSET_TAG_LEN) {
        if (memeq(cache->buffer + offset, asset_tag, LIQUID_ASSET_TAG_LEN)) {
            return true;
        }
    }
    return false;
}

#ifdef IMPLEMENT_ON_DEVICE_TESTS
#include "liquid_assets_tests.h"
#endif

#endif  // HAVE_LIQUID
