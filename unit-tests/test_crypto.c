#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/crypto.h"

// clang-format off
// HACK: define empty functions for the expected imports in cx.h and os.h.
int cx_ecfp_generate_pair ( cx_curve_t curve, cx_ecfp_public_key_t * pubkey, cx_ecfp_private_key_t * privkey, int keepprivate ){return 0;}
int cx_ecfp_generate_pair_no_throw ( cx_curve_t curve, cx_ecfp_public_key_t * pubkey, cx_ecfp_private_key_t * privkey, int keepprivate ){return 0;}
int cx_hash ( cx_hash_t * hash, int mode, const unsigned char * in, unsigned int len, unsigned char * out, unsigned int out_len ){return 0;}
int cx_ecfp_init_private_key ( cx_curve_t curve, const unsigned char * rawkey, unsigned int key_len, cx_ecfp_private_key_t * pvkey ){return 0;}
int cx_ripemd160_init ( cx_ripemd160_t * hash ){return 0;}
void os_memmove(void * dst, const void * src, unsigned int length){}
void os_perso_derive_node_bip32 ( cx_curve_t curve, const unsigned int * path, unsigned int pathLength, unsigned char * privateKey, unsigned char * chain ){}

const uint8_t uncompressed_key_02[] = {
    0x04,
    0xee,0x86,0x08,0x20,0x7e,0x21,0x02,0x84,0x26,0xf6,0x9e,0x76,0x44,0x7d,0x7e,0x3d,
    0x5e,0x07,0x70,0x49,0xf5,0xe6,0x83,0xc3,0x13,0x6c,0x23,0x14,0x76,0x2a,0x47,0x18,
    0xb4,0x5f,0x52,0x24,0xb0,0x5e,0xbb,0xad,0x09,0xf4,0x35,0x94,0xb7,0xbd,0x8d,0xc0,
    0xef,0xf4,0x51,0x9a,0x07,0xcb,0xab,0x37,0xec,0xc6,0x6e,0x00,0x01,0xab,0x95,0x9a  // even
};
const uint8_t compressed_key_02[] = {
    0x02,
    0xee,0x86,0x08,0x20,0x7e,0x21,0x02,0x84,0x26,0xf6,0x9e,0x76,0x44,0x7d,0x7e,0x3d,
    0x5e,0x07,0x70,0x49,0xf5,0xe6,0x83,0xc3,0x13,0x6c,0x23,0x14,0x76,0x2a,0x47,0x18
};


const uint8_t uncompressed_key_03[] = {
    0x04,
    0xdf,0x94,0x6e,0x0b,0x3f,0x6a,0xd7,0xf3,0x55,0x6b,0x53,0x71,0x62,0xf3,0x9f,0x07,
    0xfa,0x04,0x60,0x63,0x41,0x26,0x5f,0xe9,0x95,0xf3,0xfa,0x51,0x1f,0x7f,0xc2,0x13,
    0x1d,0x5e,0x56,0x4f,0xc5,0x1b,0x4f,0xb9,0x1a,0x83,0x67,0x73,0x3b,0x97,0xc7,0x6a,
    0x5c,0x99,0x70,0x5d,0x7e,0x99,0x12,0x59,0xb7,0x9d,0x8c,0xa3,0x65,0x35,0x09,0xcb // odd
};
const uint8_t compressed_key_03[] = {
    0x03,
    0xdf,0x94,0x6e,0x0b,0x3f,0x6a,0xd7,0xf3,0x55,0x6b,0x53,0x71,0x62,0xf3,0x9f,0x07,
    0xfa,0x04,0x60,0x63,0x41,0x26,0x5f,0xe9,0x95,0xf3,0xfa,0x51,0x1f,0x7f,0xc2,0x13
};


const uint8_t uncompressed_key_invalid[] = {
    0x05, // does not start with 0x04; invalid
    0xdf,0x94,0x6e,0x0b,0x3f,0x6a,0xd7,0xf3,0x55,0x6b,0x53,0x71,0x62,0xf3,0x9f,0x07,
    0xfa,0x04,0x60,0x63,0x41,0x26,0x5f,0xe9,0x95,0xf3,0xfa,0x51,0x1f,0x7f,0xc2,0x13,
    0x1d,0x5e,0x56,0x4f,0xc5,0x1b,0x4f,0xb9,0x1a,0x83,0x67,0x73,0x3b,0x97,0xc7,0x6a,
    0x5c,0x99,0x70,0x5d,0x7e,0x99,0x12,0x59,0xb7,0x9d,0x8c,0xa3,0x65,0x35,0x09,0xcb // odd
};
// clang-format on

static void test_get_compressed_pubkey_02(void **state) {
    (void) state;

    uint8_t key_in[65], key_out[33];
    memcpy(key_in, uncompressed_key_02, 65);
    int ret = crypto_get_compressed_pubkey(key_in, key_out);

    assert_int_equal(ret, 0);

    assert_memory_equal(key_out, compressed_key_02, 33);
    assert_memory_equal(key_in, uncompressed_key_02, 65);
}

static void test_get_compressed_pubkey_03(void **state) {
    (void) state;

    uint8_t key_in[65], key_out[33];
    memcpy(key_in, uncompressed_key_03, 65);
    int ret = crypto_get_compressed_pubkey(key_in, key_out);

    assert_int_equal(ret, 0);

    assert_memory_equal(key_out, compressed_key_03, 33);
    assert_memory_equal(key_in, uncompressed_key_03, 65);
}

// Test that it also works if key_out == key_in
static void test_get_compressed_pubkey_in_place(void **state) {
    (void) state;

    uint8_t key_in_out[65];
    memcpy(key_in_out, uncompressed_key_02, 65);
    int ret = crypto_get_compressed_pubkey(key_in_out, key_in_out);

    assert_int_equal(ret, 0);

    assert_memory_equal(key_in_out, compressed_key_02, 33);
}

static void test_get_compressed_pubkey_invalid(void **state) {
    (void) state;

    uint8_t key_in[65], key_out[33];
    memcpy(key_in, uncompressed_key_invalid, 65);
    int ret = crypto_get_compressed_pubkey(key_in, key_out);

    assert_int_equal(ret, -1);
}

static void test_validate_serialized_extended_pubkey(void **state) {
    (void) state;

    // Testnet extended public key
    int ret = validate_serialized_extended_pubkey(
        "tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g",
        (uint32_t[]){
            48 | BIP32_FIRST_HARDENED_CHILD,
            1  | BIP32_FIRST_HARDENED_CHILD,
            0  | BIP32_FIRST_HARDENED_CHILD,
            1  | BIP32_FIRST_HARDENED_CHILD
        },
        4,
        0x043587cf
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_VALID);

    // Mainnet extended public key
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        (uint32_t[]){ 12345 },
        1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_VALID);

    // Validation without path checking
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        NULL,
        -1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_VALID);

    // Master public key
    ret = validate_serialized_extended_pubkey(
        "xpub661MyMwAqRbcEnKbXcCqD2GT1di5zQxVqoHPAgHNe8dv5JP8gWmDproS6kFHJnLZd23tWevhdn4urGJ6b264DfTGKr8zjmYDjyDTi9U7iyT",
        NULL,
        0,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_VALID);
}

static void test_validate_serialized_extended_pubkey_invalid(void **state) {
    (void) state;

    // Invalid argument: NULL as pubkey
    int ret = validate_serialized_extended_pubkey(
        NULL, (uint32_t[]){ 12345 },  1, 0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_ARGUMENT);

    // Invalid argument: path is too long
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        (uint32_t[]){ 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        9,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_ARGUMENT);

    // Invalid argument: path is NULL
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        NULL,
        1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_ARGUMENT);

    // Invalid argument: pubkey string is too long
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8aZZZ",
        (uint32_t[]){ 12345 },
        1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_ARGUMENT);

    // Invalid symbol in Base58 string
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1\x01TdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        (uint32_t[]){ 12345 },
        1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_BASE58_CODE);

    // Corrupted Base58 string, resulting in invalid checksum
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1ZTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        (uint32_t[]){ 12345 },
        1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_CHECKSUM);

    // Invalid version
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        (uint32_t[]){ 12345 },
        1,
        0x0488b21e + 1
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_VERSION);

    // Invalid depth
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        (uint32_t[]){ 12345, 12345 },
        2,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_DEPTH);

    // Invalid child number
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj5WXzFpdSQEN7mb5oZ2Ade3iHXjugxqtKfz2QrGDpCRiq6Dxz8a",
        (uint32_t[]){ 12345 + 1 },
        1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_CHILD_NUMBER);

    // Invalid pubkey prefix (0x04 instead of 0x03)
    ret = validate_serialized_extended_pubkey(
        "xpub67ymn1YTdEC4wRwy5ghTuuHuVw8N3rA9a5fvoQaPam1ud9sPMPbiXoBgj7THAVGfHpubFbAni8eAaxeVCeMdLfgm7K48ezx7orS7Kf927RD",
        (uint32_t[]){ 12345 },
        1,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_PREFIX);

    // Master public key with invalid child number (1 instead of 0)
    ret = validate_serialized_extended_pubkey(
        "xpub661MyMwAqRbcHL9a4ZxvDZLQxPGcjJoDnLYGfD5sRV7HfNc32EkPCfWdNz6sHyrVFvRz4G7DYkhhtsFf3wDMQxbySGcpBwLGaXehDhe9yQ7",
        NULL,
        0,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_CHILD_NUMBER);

    // Master public key with invalid parent's fingerprint (1 instead of 0)
    ret = validate_serialized_extended_pubkey(
        "xpub661MyMwTWkfYbLu9LWUcdQVBEWceNbmdb7s91e4jSdrkh7isZFDVKhLysNT3Kr1TiLyoS3X3LMrn3WXs5pbh8uHD3EzACEUsZEvHUfUF5ro",
        NULL,
        0,
        0x0488b21e
    );
    assert_int_equal(ret, EXTENDED_PUBKEY_INVALID_PARENT_FINGERPRINT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_compressed_pubkey_02),
        cmocka_unit_test(test_get_compressed_pubkey_03),
        cmocka_unit_test(test_get_compressed_pubkey_in_place),
        cmocka_unit_test(test_get_compressed_pubkey_invalid),
        cmocka_unit_test(test_validate_serialized_extended_pubkey),
        cmocka_unit_test(test_validate_serialized_extended_pubkey_invalid)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
