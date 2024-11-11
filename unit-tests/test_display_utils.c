#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "ui/display_utils.h"

static const struct {
    const char *coin;
    uint64_t amount;
    uint8_t decimals;
    const char *expected;
} sats_testcases[] = {
    {.coin = "BTC", .amount = 0LLU, .decimals = 8, .expected = "BTC 0"},
    {.coin = "BTC", .amount = 1LLU, .decimals = 8, .expected = "BTC 0.00000001"},
    {.coin = "BTC", .amount = 10LLU, .decimals = 8, .expected = "BTC 0.0000001"},
    {.coin = "BTC", .amount = 100LLU, .decimals = 8, .expected = "BTC 0.000001"},
    {.coin = "BTC", .amount = 1000LLU, .decimals = 8, .expected = "BTC 0.00001"},
    {.coin = "BTC", .amount = 10000LLU, .decimals = 8, .expected = "BTC 0.0001"},
    {.coin = "BTC", .amount = 100000LLU, .decimals = 8, .expected = "BTC 0.001"},
    {.coin = "BTC", .amount = 1000000LLU, .decimals = 8, .expected = "BTC 0.01"},
    {.coin = "BTC", .amount = 10000000LLU, .decimals = 8, .expected = "BTC 0.1"},
    {.coin = "BTC", .amount = 100000000LLU, .decimals = 8, .expected = "BTC 1"},
    {.coin = "TEST", .amount = 234560000LLU, .decimals = 8, .expected = "TEST 2.3456"},
    {.coin = "TEST",
     .amount = 21000000LLU * 100000000LLU,
     .decimals = 8,
     .expected = "TEST 21000000"},
    {.coin = "TICKR",  // ticker supported up to 5 characters
     .amount = 18446744073709551615LLU,
     .decimals = 8,
     .expected = "TICKR 184467440737.09551615"},  // largest possible uint64_t

    // 3 decimal digits
    {.coin = "XYZ", .amount = 0LLU, .decimals = 3, .expected = "XYZ 0"},
    {.coin = "XYZ", .amount = 1LLU, .decimals = 3, .expected = "XYZ 0.001"},
    {.coin = "XYZ", .amount = 10LLU, .decimals = 3, .expected = "XYZ 0.01"},
    {.coin = "XYZ", .amount = 100LLU, .decimals = 3, .expected = "XYZ 0.1"},
    {.coin = "XYZ", .amount = 1000LLU, .decimals = 3, .expected = "XYZ 1"},
    {.coin = "XYZ", .amount = 10000LLU, .decimals = 3, .expected = "XYZ 10"},
    {.coin = "XYZ", .amount = 100000LLU, .decimals = 3, .expected = "XYZ 100"},
    {.coin = "XYZ", .amount = 1000000LLU, .decimals = 3, .expected = "XYZ 1000"},
    {.coin = "XYZ", .amount = 10000000LLU, .decimals = 3, .expected = "XYZ 10000"},
    {.coin = "XYZ", .amount = 100000000LLU, .decimals = 3, .expected = "XYZ 100000"},
    {.coin = "TEST", .amount = 23456LLU, .decimals = 3, .expected = "TEST 23.456"},
    {.coin = "TICKR",  // ticker supported up to 5 characters
     .amount = 18446744073709551615LLU,
     .decimals = 3,
     .expected = "TICKR 18446744073709551.615"},  // largest possible uint64_t

    // various decimal digits, largest possible uint64_t
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 0,
     .expected = "TICKR 18446744073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 1,
     .expected = "TICKR 1844674407370955161.5"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 2,
     .expected = "TICKR 184467440737095516.15"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 3,
     .expected = "TICKR 18446744073709551.615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 4,
     .expected = "TICKR 1844674407370955.1615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 5,
     .expected = "TICKR 184467440737095.51615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 6,
     .expected = "TICKR 18446744073709.551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 7,
     .expected = "TICKR 1844674407370.9551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 8,
     .expected = "TICKR 184467440737.09551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 9,
     .expected = "TICKR 18446744073.709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 10,
     .expected = "TICKR 1844674407.3709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 11,
     .expected = "TICKR 184467440.73709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 12,
     .expected = "TICKR 18446744.073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 13,
     .expected = "TICKR 1844674.4073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 14,
     .expected = "TICKR 184467.44073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 15,
     .expected = "TICKR 18446.744073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 16,
     .expected = "TICKR 1844.6744073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 17,
     .expected = "TICKR 184.46744073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 18,
     .expected = "TICKR 18.446744073709551615"},
    {.coin = "TICKR",
     .amount = 18446744073709551615LLU,
     .decimals = 19,
     .expected = "TICKR 1.8446744073709551615"},

    // various decimal digits, amount = 12345
    {.coin = "TEST", .amount = 12345LLU, .decimals = 0, .expected = "TEST 12345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 1, .expected = "TEST 1234.5"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 2, .expected = "TEST 123.45"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 3, .expected = "TEST 12.345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 4, .expected = "TEST 1.2345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 5, .expected = "TEST 0.12345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 6, .expected = "TEST 0.012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 7, .expected = "TEST 0.0012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 8, .expected = "TEST 0.00012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 9, .expected = "TEST 0.000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 10, .expected = "TEST 0.0000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 11, .expected = "TEST 0.00000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 12, .expected = "TEST 0.000000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 13, .expected = "TEST 0.0000000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 14, .expected = "TEST 0.00000000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 15, .expected = "TEST 0.000000000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 16, .expected = "TEST 0.0000000000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 17, .expected = "TEST 0.00000000000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 18, .expected = "TEST 0.000000000000012345"},
    {.coin = "TEST", .amount = 12345LLU, .decimals = 19, .expected = "TEST 0.0000000000000012345"},
};

static void test_format_amount(void **state) {
    (void) state;

    for (unsigned int i = 0; i < sizeof(sats_testcases) / sizeof(sats_testcases[0]); i++) {
        char out[MAX_AMOUNT_LENGTH * 2 + 1];
        memset(out, 0xEE, sizeof(out));

        format_amount(sats_testcases[i].coin,
                      sats_testcases[i].amount,
                      sats_testcases[i].decimals,
                      out);
        out[sizeof(out) - 1] = '\0';
        assert_string_equal((char *) out, sats_testcases[i].expected);

        // Check for buffer overflow
        for (int i = MAX_AMOUNT_LENGTH + 1; i < sizeof(out) - 1; ++i) {
            assert_int_equal((int) (unsigned char) out[i], 0xEE);
        }
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_format_amount)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
