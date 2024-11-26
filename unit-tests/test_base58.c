#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/base58.h"

static void test_base58(void **state) {
    (void) state;

    const char in[] = "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z";
    const char expected_out[] = "The quick brown fox jumps over the lazy dog.";
    uint8_t out[100] = {0};
    int out_len = base58_decode(in, sizeof(in) - 1, out, sizeof(out));
    assert_int_equal(out_len, strlen(expected_out));
    assert_string_equal((char *) out, expected_out);

    const char in2[] = "The quick brown fox jumps over the lazy dog.";
    const char expected_out2[] = "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z";
    char out2[100] = {0};
    int out_len2 = base58_encode((uint8_t *) in2, sizeof(in2) - 1, out2, sizeof(out2));
    assert_int_equal(out_len2, strlen(expected_out2));
    assert_string_equal((char *) out2, expected_out2);
}

static void test_base58_checksum(void **state) {
    (void) state;

    const uint8_t in[] = {0x80, 0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B,
                          0x2F, 0xE5, 0x0B, 0x7C, 0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F,
                          0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1, 0x9D, 0x72, 0xAA, 0x1D};

    uint32_t checksum = base58_checksum(in, sizeof(in));
    assert_int_equal(checksum, 0x507A5B8D);
}

int main(void) {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_base58),
                                       cmocka_unit_test(test_base58_checksum)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
