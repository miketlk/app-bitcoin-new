#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "liquid/liquid_addr.h"

// TODO: add failure tests

static void test_liquid_encode_address_base58(void **state) {
    (void) state;

    const uint8_t pubkey_hash[] = {0x73, 0xFA, 0x58, 0x0E, 0xA1, 0x48, 0xBF, 0x5A, 0x52, 0x0E,
                                   0x21, 0xA9, 0xE6, 0xA8, 0x75, 0xD3, 0x86, 0x03, 0xDF, 0x96};
    const uint8_t blinding_pubkey[] = {0x02, 0xDC, 0xE1, 0x60, 0x18, 0xBB, 0xBB, 0x8E, 0x36,
                                       0xDE, 0x7B, 0x39, 0x4D, 0xF5, 0xB5, 0x16, 0x6E, 0x9A,
                                       0xDB, 0x74, 0x98, 0xBE, 0x7D, 0x88, 0x1A, 0x85, 0xA0,
                                       0x9A, 0xEE, 0xCF, 0x76, 0xB6, 0x23};
    const char ref_conf_addr[] =
        "VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK";
    const uint32_t CA_PREFIX_LIQUID = 0x0C;
    const uint32_t VERSION_P2PKH_LIQUID_V1 = 0x39;
    char conf_addr[sizeof(ref_conf_addr)] = "";

    int ret = liquid_encode_address_base58(pubkey_hash,
                                           sizeof(pubkey_hash),
                                           CA_PREFIX_LIQUID,
                                           VERSION_P2PKH_LIQUID_V1,
                                           blinding_pubkey,
                                           sizeof(blinding_pubkey),
                                           conf_addr,
                                           sizeof(conf_addr));

    assert_int_equal(ret, sizeof(ref_conf_addr) - 1);
    assert_string_equal(conf_addr, ref_conf_addr);
}

static void test_liquid_encode_address_segwit_v0(void **state) {
    (void) state;

    const uint8_t witprog[] = {0xE6, 0xA1, 0x0B, 0x7B, 0xD8, 0xAE, 0xB5, 0x64, 0x44, 0xC5,
                               0x73, 0x4E, 0xA6, 0x82, 0xCD, 0x2F, 0x1A, 0xD6, 0x92, 0xC4};
    const uint8_t blinding_pubkey[] = {0x03, 0xA3, 0x98, 0xEE, 0xD5, 0x9A, 0x23, 0x68, 0x56,
                                       0x3B, 0xBD, 0x2B, 0xC6, 0x8A, 0x7C, 0xCD, 0xBB, 0xD6,
                                       0xDC, 0xBF, 0x43, 0xB2, 0x98, 0xED, 0xC8, 0x10, 0xD2,
                                       0x2E, 0xDB, 0x6D, 0x76, 0x18, 0x00};
    const char prefix[] = "el";
    const uint32_t version = 0;
    const char ref_conf_addr[] =
        "el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvg"
        "zaclqjnkz0sd";

    char conf_addr[sizeof(ref_conf_addr)] = "";

    int ret = liquid_encode_address_segwit(witprog,
                                           sizeof(witprog),
                                           prefix,
                                           version,
                                           blinding_pubkey,
                                           sizeof(blinding_pubkey),
                                           conf_addr,
                                           sizeof(conf_addr));

    assert_int_equal(ret, sizeof(ref_conf_addr) - 1);
    assert_string_equal(conf_addr, ref_conf_addr);
}

static void test_liquid_encode_address_segwit_v1(void **state) {
    (void) state;

    const uint8_t witprog[] = {0xD0, 0xD1, 0xF8, 0xC5, 0xB1, 0x81, 0x5B, 0xC4, 0x71, 0xAE, 0xF4,
                               0xF4, 0x72, 0x0C, 0x64, 0xEC, 0xAC, 0x38, 0xDF, 0xA5, 0x01, 0xC0,
                               0xAA, 0xC9, 0x4F, 0x14, 0x34, 0xA8, 0x66, 0xA0, 0x2A, 0xE0};
    const uint8_t blinding_pubkey[] = {0x02, 0xBB, 0x66, 0x71, 0x0A, 0xCF, 0xD4, 0x34, 0x6B,
                                       0xEB, 0xD7, 0x72, 0xEB, 0x94, 0x62, 0x27, 0x9A, 0x8F,
                                       0xA4, 0xBD, 0x93, 0x76, 0x3B, 0x5A, 0x73, 0x73, 0xBF,
                                       0x19, 0x38, 0xC8, 0x4D, 0xAE, 0x53};
    const char prefix[] = "tex";
    const uint32_t version = 1;
    const char ref_conf_addr[] =
        "tex1pq2akvug2el2rg6lt6aewh9rzy7dglf9ajdmrkknnwwl3jwxgfkh985x3lrzmrq2mc3c6aa85wgxxfm9v8r06"
        "2qwq4ty579p54pn2q2hq2g5wad8z6kmm";

    char conf_addr[sizeof(ref_conf_addr)] = "";

    int ret = liquid_encode_address_segwit(witprog,
                                           sizeof(witprog),
                                           prefix,
                                           version,
                                           blinding_pubkey,
                                           sizeof(blinding_pubkey),
                                           conf_addr,
                                           sizeof(conf_addr));

    assert_int_equal(ret, sizeof(ref_conf_addr) - 1);
    assert_string_equal(conf_addr, ref_conf_addr);
}

static void test_liquid_encode_address_taproot(void **state) {
    (void) state;

    const uint8_t script[] = {0x51, 0x20, 0x74, 0x0E, 0xE6, 0x4E, 0x45, 0x2E, 0x3B,
                              0xAE, 0xE1, 0x27, 0xB0, 0x3C, 0x19, 0x5B, 0xCC, 0x21,
                              0xAD, 0x3E, 0xDD, 0xED, 0x2E, 0xF2, 0x6C, 0x5A, 0xF4,
                              0x83, 0xD9, 0xC5, 0x63, 0x04, 0xD1, 0xE5};
    const uint8_t blinding_pubkey[] = {0x02, 0x1F, 0xE2, 0x41, 0xD1, 0x83, 0xE6, 0x73, 0x30,
                                       0x0F, 0x03, 0xF2, 0x73, 0x19, 0x5D, 0x83, 0xDB, 0x44,
                                       0x1C, 0xFC, 0x4E, 0x51, 0xBE, 0x6E, 0x97, 0x07, 0xF6,
                                       0xEC, 0x6F, 0x9E, 0x5A, 0xA9, 0x70};
    const char prefix[] = "el";
    const char ref_addr[] =
        "el1pqg07ysw3s0n8xvq0q0e8xx2as0d5g88ufegmum5hqlmwcmu7t25hqaqwue8y2t3m4msj0vpur9ducgdd8mw76"
        "thjd3d0fq7ec43sf509vzd04meg4245";
    char addr[sizeof(ref_addr)] = "";

    int ret = liquid_encode_address_segwit(script + 2,
                                           script[1],
                                           prefix,
                                           script[0] - 80,
                                           blinding_pubkey,
                                           sizeof(blinding_pubkey),
                                           addr,
                                           sizeof(addr));

    assert_int_equal(ret, sizeof(ref_addr) - 1);
    assert_string_equal(addr, ref_addr);
}

int main(void) {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_liquid_encode_address_base58),
                                       cmocka_unit_test(test_liquid_encode_address_segwit_v0),
                                       cmocka_unit_test(test_liquid_encode_address_segwit_v1),
                                       cmocka_unit_test(test_liquid_encode_address_taproot)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
