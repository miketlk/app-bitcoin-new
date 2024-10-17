#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "os.h"
#include "./display_utils.h"

/// Descriptor of sighash flag combination
typedef struct {
    sighash_name_t name;
    uint32_t sighash;
} sighash_descriptor_t;

// clang-format off
/// Table of known sighash types
static const sighash_descriptor_t KNOWN_SIGHASH_TYPES[] = {
    { .name = {1, {"DEFAULT"}},                              .sighash = (SIGHASH_DEFAULT) },
    { .name = {1, {"ALL"}},                                  .sighash = (SIGHASH_ALL) },
    { .name = {2, {"ALL", "ANYONECANPAY"}},                  .sighash = (SIGHASH_ALL|SIGHASH_ANYONECANPAY) },
    { .name = {1, {"NONE"}},                                 .sighash = (SIGHASH_NONE)},
    { .name = {2, {"NONE", "ANYONECANPAY"}},                 .sighash = (SIGHASH_NONE|SIGHASH_ANYONECANPAY) },
    { .name = {1, {"SINGLE"}},                               .sighash = (SIGHASH_SINGLE) },
    { .name = {2, {"SINGLE", "ANYONECANPAY"}},               .sighash = (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY) },
#ifdef HAVE_LIQUID
    { .name = {2, {"ALL", "RANGEPROOF"}},                    .sighash = (SIGHASH_ALL|SIGHASH_RANGEPROOF) },
    { .name = {3, {"ALL", "ANYONECANPAY", "RANGEPROOF"}},    .sighash = (SIGHASH_ALL|SIGHASH_ANYONECANPAY|SIGHASH_RANGEPROOF) },
    { .name = {2, {"NONE", "RANGEPROOF"}},                   .sighash = (SIGHASH_NONE|SIGHASH_RANGEPROOF) },
    { .name = {3, {"NONE", "ANYONECANPAY", "RANGEPROOF"}},   .sighash = (SIGHASH_NONE|SIGHASH_ANYONECANPAY|SIGHASH_RANGEPROOF) },
    { .name = {2, {"SINGLE", "RANGEPROOF"}},                 .sighash = (SIGHASH_SINGLE|SIGHASH_RANGEPROOF) },
    { .name = {3, {"SINGLE", "ANYONECANPAY", "RANGEPROOF"}}, .sighash = (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY|SIGHASH_RANGEPROOF) },
#endif // HAVE_LIQUID
};
// clang-format on

// Number of descriptors in the table of known sighash types
static const size_t N_KNOWN_SIGHASH_TYPES =
    sizeof(KNOWN_SIGHASH_TYPES) / sizeof(KNOWN_SIGHASH_TYPES[0]);

// Constatnt name for an unknown sighash type.
const sighash_name_t sighash_name_unknown = { 1, {"UNKNOWN"} };

// Division and modulus operators over uint64_t causes the inclusion of the __udivmoddi4 and other
// library functions that occupy more than 400 bytes. Since performance is not critical and division
// by 10 is sufficient, we avoid it with a binary search instead.
static uint64_t div10(uint64_t n) {
    if (n < 10) return 0;  // special case needed to make sure that n - 10 is safe

    // Since low, mid and high are always <= UINT64_MAX / 10, there is no risk of overflow
    uint64_t low = 0;
    uint64_t high = UINT64_MAX / 10;

    while (true) {
        uint64_t mid = (low + high) / 2;

        // the result equals mid if and only if mid * 10 <= n < mid * 10 + 10
        // care is taken to make sure overflows and underflows are impossible
        if (mid * 10 > n - 10 && n >= mid * 10) {
            return mid;
        } else if (n < mid * 10) {
            high = mid - 1;
        } else /* n >= 10 * mid + 10 */ {
            low = mid + 1;
        }
    }
}

static uint64_t div_pow10(uint64_t n, uint8_t pow10) {
    uint64_t res = n;
    for (int i = 0; i < pow10; i++) res = div10(res);
    return res;
}

static uint64_t mul_pow10(uint64_t n, uint8_t pow10) {
    uint64_t res = n;
    for (int i = 0; i < pow10; i++) res = res * (uint8_t)10;
    return res;
}

static size_t n_digits(uint64_t number) {
    size_t count = 0;
    do {
        count++;

        // HACK: avoid __udivmoddi4
        // number /= 10;

        number = div10(number);
    } while (number != 0);
    return count;
}

void format_amount(const char *coin_name,
                   uint64_t amount,
                   uint8_t decimals,
                   char out[static MAX_AMOUNT_LENGTH + 1]) {
    if (!out) {
        return;
    }
    strlcpy(out, "<ERROR>", MAX_AMOUNT_LENGTH + 1);
    if (!coin_name || decimals > 19) {
        return;
    }
    size_t coin_name_len = strnlen(coin_name, MAX_ASSET_TICKER_LENGTH + 1);
    if (coin_name_len > MAX_ASSET_TICKER_LENGTH) {
        return;
    }

    strlcpy(out, coin_name, MAX_AMOUNT_LENGTH + 1);
    out[coin_name_len] = ' ';

    char *amount_str = out + coin_name_len + 1;

    // HACK: avoid __udivmoddi4
    // uint64_t integral_part = amount / (10 ^ decimals);
    // uint32_t fractional_part = (uint32_t) (amount % (10 ^ decimals));
    uint64_t integral_part = div_pow10(amount, decimals);
    uint64_t fractional_part = amount - mul_pow10(integral_part, decimals);

    // format the integral part, starting from the least significant digit
    size_t integral_part_digit_count = n_digits(integral_part);
    for (unsigned int i = 0; i < integral_part_digit_count; i++) {
        // HACK: avoid __udivmoddi4
        // amount_str[integral_part_digit_count - 1 - i] = '0' + (integral_part % 10);
        // integral_part /= 10;

        uint64_t tmp_quotient = div10(integral_part);
        char tmp_remainder = (char) (integral_part - 10 * tmp_quotient);
        amount_str[integral_part_digit_count - 1 - i] = '0' + tmp_remainder;
        integral_part = tmp_quotient;
    }

    if (fractional_part == 0 || decimals == 0) {
        amount_str[integral_part_digit_count] = '\0';
    } else {
        amount_str[integral_part_digit_count] = '.';
        size_t fractional_part_digit_count = n_digits(fractional_part);
        char *fract_part_str = amount_str + integral_part_digit_count + 1;
        // add leading zeroes according to specified `decimals`
        for (unsigned int i = 0; i < decimals - fractional_part_digit_count; i++) {
            *fract_part_str++ = '0';
        }
        // convert fractional part to characters
        for (unsigned int i = 0; i < fractional_part_digit_count; i++) {
            uint64_t tmp_quotient = div10(fractional_part);
            char tmp_remainder = (char) (fractional_part - 10 * tmp_quotient);
            fract_part_str[fractional_part_digit_count - 1 - i] = '0' + tmp_remainder;
            fractional_part = tmp_quotient;
        }
        fract_part_str[fractional_part_digit_count] = '\0';
        // drop trailing zeros
        fract_part_str = amount_str + integral_part_digit_count + 1;
        for (int i = decimals - 1; i > 0 && fract_part_str[i] == '0'; i--) {
            fract_part_str[i] = '\0';
        }
    }
}

void sighash_get_name(sighash_name_t* name, uint32_t sighash_type) {
    const sighash_descriptor_t *dsc = PIC(KNOWN_SIGHASH_TYPES);
    for (size_t i = 0; i < N_KNOWN_SIGHASH_TYPES; ++i, ++dsc) {
        if (sighash_type == dsc->sighash) {
            *name = dsc->name;
            return;
        }
    }
    *name = *((const sighash_name_t* ) PIC(&sighash_name_unknown));
}