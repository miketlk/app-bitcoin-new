#pragma once

#include <stdint.h>

#include "../constants.h"
#include "../util.h"

/// Maximum amount length
// up to 5 chars for ticker, 1 space, up to 20 digits (20 = digits of 2^64), + 1 decimal separator
#define MAX_AMOUNT_LENGTH (MAX_ASSET_TICKER_LENGTH + 1 + 20 + 1)

/// Maximum length of the textual representation of a sighash flag.
#define MAX_SIGHASH_FLAG_LENGTH \
    (MAX7_SIZEOF("DEFAULT", "ALL", "NONE", "SINGLE", "ANYONECANPAY", "RANGEPROOF", "UNKNOWN") - 1)

/// Maximum number of flags in sighash type
#define MAX_SIGHASH_FLAGS 3

/// Name of sighash type, composed of individual flags
typedef struct {
    size_t n_flags;
    char flags[MAX_SIGHASH_FLAGS][MAX_SIGHASH_FLAG_LENGTH + 1];
} sighash_name_t;

/**
 * Converts a 64-bits unsigned integer into a decimal representation. Trailing decimal zeros are not
 * appended (and no decimal point is present if the `amount` is a multiple of 10 ^ `decimals`). The
 * resulting string is prefixed with a ticker name (up to 5 characters long), followed by a space.
 *
 * @param coin_name a zero-terminated ticker name, at most 5 characterso long (not including the
 * terminating 0)
 * @param amount the amount to format
 * @param decimals the number of decimal digits in fractional part
 * @param out the output array which must be at least MAX_AMOUNT_LENGTH + 1 bytes long
 */
void format_amount(const char *coin_name,
                   uint64_t amount,
                   uint8_t decimals,
                   char out[static MAX_AMOUNT_LENGTH + 1]);

/**
 * Converts a 64-bits unsigned integer into a decimal rapresentation, where the `amount` is a
 * multiple of 1/100_000_000th. Trailing decimal zeros are not appended (and no decimal point is
 * present if the `amount` is a multiple of 100_000_000). The resulting string is prefixed with a
 * ticker name (up to 5 characters long), followed by a space.
 *
 * @param coin_name a zero-terminated ticker name, at most 5 characterso long (not including the
 * terminating 0)
 * @param amount the amount to format
 * @param out the output array which must be at least MAX_AMOUNT_LENGTH + 1 bytes long
 */
static inline void format_sats_amount(const char *coin_name,
                                      uint64_t amount,
                                      char out[static MAX_AMOUNT_LENGTH + 1]) {
    format_amount(coin_name, amount, BITCOIN_DECIMALS, out);
}

/**
 * Returns the name of the given sighash type.
 *
 * @param[out] name pointer to structure instance, receiving components of sighash name.
 * @param[in] sighash_type sighash type: a combination of bit flags.
 */
void sighash_get_name(sighash_name_t *name, uint32_t sighash_type);
