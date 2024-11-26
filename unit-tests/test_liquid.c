#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "liquid/liquid.h"

// in unit tests, size_t integers are currently 8 compiled as 8 bytes; therefore, in the app
// about half of the memory would be needed
#define MAX_POLICY_MAP_MEMORY_SIZE 512

// Version bytes of Liquid regtest xpub
#define LIQUID_REGTEST_XPUB 0x043587CF
// Version bytes of Liquid regtest xprv
#define LIQUID_REGTEST_XPRV 0x04358394
// Version bytes of Liquid main network (liquidv1) xpub
#define LIQUID_MAIN_XPUB 0x0488B21E
// Version bytes of Liquid main network (liquidv1) xprv
#define LIQUID_MAIN_XPRV 0x0488ADE4

#if defined(BIP32_PUBKEY_VERSION) || defined(BIP32_PRIVKEY_VERSION)
#error Macros BIP32_PUBKEY_VERSION and BIP32_PRIVKEY_VERSION must be undefined to allow mocking
#endif

// Mock BIP32_PUBKEY_VERSION and BIP32_PRIVKEY_VERSION macros with global variables
uint32_t BIP32_PUBKEY_VERSION = LIQUID_REGTEST_XPUB;
uint32_t BIP32_PRIVKEY_VERSION = LIQUID_REGTEST_XPRV;

const liquid_network_config_t config_elementsregtest = {.p2pkh_version = 0x6F,
                                                        .p2sh_version = 0x4B,
                                                        .prefix_confidential = 0x04,
                                                        .segwit_prefix = "ert",
                                                        .segwit_prefix_confidential = "el"};

// Convenience function to parse policy as one liners
static int parse_policy(const char *policy,
                        size_t policy_len,
                        uint8_t *out,
                        size_t out_len,
                        uint32_t bip32_pubkey_version,
                        uint32_t bip32_privkey_version) {
    BIP32_PUBKEY_VERSION = bip32_pubkey_version;
    BIP32_PRIVKEY_VERSION = bip32_privkey_version;
    buffer_t in_buf = buffer_create((void *) policy, policy_len);
    return parse_descriptor_template(&in_buf, out, out_len, WALLET_POLICY_VERSION_V2);
}

#define PARSE_POLICY(policy, out, out_len) \
    parse_policy(policy, sizeof(policy) - 1, out, out_len, LIQUID_MAIN_XPUB, LIQUID_MAIN_XPRV)
#define PARSE_POLICY_EXT(policy, out, out_len, vpubkey, vprivkey) \
    parse_policy(policy, sizeof(policy) - 1, out, out_len, vpubkey, vprivkey)

static void test_liquid_get_script_confidential_address_segwit(void **state) {
    (void) state;

    const uint8_t blinding_key[] = {0x03, 0xB8, 0x45, 0xC0, 0x3A, 0x30, 0xC1, 0x7E, 0x5B,
                                    0x95, 0xC0, 0x00, 0x95, 0xB7, 0xB0, 0x62, 0x74, 0xDD,
                                    0x0E, 0xC6, 0x97, 0xC6, 0x92, 0xBC, 0x2B, 0xDC, 0x75,
                                    0xE7, 0xAC, 0xCA, 0x0D, 0x9D, 0xF4};
    // ct(slip77(MBK),wsh(...))
    const uint8_t script[] = {0x00, 0x20, 0xDB, 0xDF, 0x82, 0xD0, 0x2C, 0xB4, 0x82,
                              0x5F, 0x25, 0x90, 0x74, 0x3E, 0xF2, 0xCB, 0xC1, 0x42,
                              0xFD, 0x4D, 0xD2, 0xB0, 0x18, 0xA1, 0xC5, 0x10, 0xFE,
                              0x77, 0x79, 0xE6, 0x55, 0x51, 0x02, 0xAC};
    const char ref_addr[] =
        "el1qqwuytsp6xrqhuku4cqqftdasvf6d6rkxjlrf90ptm3670tx2pkwlfk7lstgzedyzt"
        "ujeqap77t9uzshafhftqx9pc5g0uameue24zq4vcu0n02rjs05c";
    char addr[sizeof(ref_addr)] = "";

    int addr_len = liquid_get_script_confidential_address(script,
                                                          sizeof(script),
                                                          &config_elementsregtest,
                                                          blinding_key,
                                                          sizeof(blinding_key),
                                                          addr,
                                                          sizeof(addr));

    assert_int_equal(addr_len, sizeof(ref_addr) - 1);
    assert_string_equal(addr, ref_addr);
}

static void test_liquid_get_script_confidential_address_p2sh(void **state) {
    (void) state;

    const uint8_t blinding_key[] = {0x03, 0x03, 0xE2, 0xAC, 0xCC, 0x2B, 0x85, 0x98, 0x61,
                                    0xAE, 0x0D, 0x43, 0x93, 0xF9, 0x7D, 0xB5, 0xE2, 0x4C,
                                    0xA5, 0x4D, 0x53, 0x8A, 0x77, 0x13, 0x01, 0xA6, 0x27,
                                    0x95, 0x01, 0x2A, 0x05, 0xC5, 0x56};
    // ct(slip77(MBK),sh(wpkh(...)))
    const uint8_t script[] = {0xA9, 0x14, 0x9A, 0x73, 0x7C, 0x68, 0x56, 0xFD,
                              0x6C, 0x65, 0x6D, 0x3F, 0x2C, 0x9E, 0xF4, 0xE7,
                              0x32, 0x4D, 0x35, 0x00, 0xF5, 0xD0, 0x87};
    const char ref_addr[] =
        "Azpr1TWL4x4zfj7SuzvpiT7b7fwEwBaS4ZamSbrzahbfduBkoBJHcrj2WkrjWWi4aKKyKtbugyEC1dxf";
    char addr[sizeof(ref_addr)] = "";

    int addr_len = liquid_get_script_confidential_address(script,
                                                          sizeof(script),
                                                          &config_elementsregtest,
                                                          blinding_key,
                                                          sizeof(blinding_key),
                                                          addr,
                                                          sizeof(addr));

    assert_int_equal(addr_len, sizeof(ref_addr) - 1);
    assert_string_equal(addr, ref_addr);
}

static void test_policy_unwrap_ct(void **state) {
    (void) state;

    uint8_t policy_bytes[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(
        0 <=
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),"
                     "wpkh(@0/**))",
                     policy_bytes,
                     sizeof(policy_bytes)));

    const policy_node_t *policy = policy_unwrap((const policy_node_t *) policy_bytes);

    assert_non_null(policy);
    assert_true(policy != (policy_node_t *) policy_bytes);
    assert_int_equal(policy->type, TOKEN_WPKH);  // inside ct()
}

static void test_policy_unwrap_blinded_ct(void **state) {
    (void) state;

    uint8_t policy_bytes[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(0 <= PARSE_POLICY("wpkh(@0/**)", policy_bytes, sizeof(policy_bytes)));

    const policy_node_t *policy = policy_unwrap((const policy_node_t *) policy_bytes);

    assert_non_null(policy);
    assert_true(policy == (policy_node_t *) policy_bytes);  // unchanged
    assert_int_equal(policy->type, TOKEN_WPKH);
}

static void test_parse_policy_map_blinded_slip77_singlesig(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(
        0 <=
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),"
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_privkey_t *mbk = (policy_node_blinding_privkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_SLIP77);
    static const uint8_t ref_mbk[] = {0x90, 0x5c, 0xfe, 0x33, 0xa3, 0xdf, 0xb3, 0x7d,
                                      0xb5, 0x13, 0xd1, 0x07, 0x8c, 0x16, 0xbc, 0xfd,
                                      0xf9, 0x06, 0xec, 0xd9, 0x44, 0xc5, 0xdd, 0xd3,
                                      0x7f, 0xdf, 0xbc, 0xc5, 0xe6, 0x19, 0xc1, 0x41};
    assert_memory_equal(mbk->privkey, ref_mbk, sizeof(ref_mbk));

    const policy_node_with_key_t *inner =
        (policy_node_with_key_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner);
    assert_int_equal(inner->base.type, TOKEN_WPKH);

    const policy_node_key_placeholder_t *key_placeholder =
        r_policy_node_key_placeholder(&inner->key_placeholder);
    assert_non_null(key_placeholder);
    assert_int_equal(key_placeholder->key_index, 0);
    assert_int_equal(key_placeholder->num_first, 0);
    assert_int_equal(key_placeholder->num_second, 1);
}

static void test_parse_policy_map_blinded_slip77_multisig(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(
        0 <=
        PARSE_POLICY("ct(slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5),"
                     "sh(wsh(sortedmulti(5,@0/**,@1/**,@2/**,@3/**,@4/**,@5/**,@6/**))))",
                     out,
                     sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_privkey_t *mbk = (policy_node_blinding_privkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_SLIP77);
    static const char ref_mbk[] = {0x80, 0xb7, 0x96, 0xc7, 0x6c, 0x89, 0x5b, 0xda, 0x15, 0x1c, 0xd5,
                                   0xc4, 0x0f, 0x3a, 0x11, 0xaf, 0xcd, 0x96, 0xd6, 0x6f, 0x99, 0x34,
                                   0x7a, 0x76, 0x0d, 0x3f, 0x7b, 0x8a, 0xaa, 0x58, 0x15, 0xb5};
    assert_memory_equal(mbk->privkey, ref_mbk, sizeof(ref_mbk));

    const policy_node_with_script_t *inner1 =
        (policy_node_with_script_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner1);
    assert_int_equal(inner1->base.type, TOKEN_SH);

    const policy_node_with_script_t *inner2 =
        (policy_node_with_script_t *) r_policy_node(&inner1->script);
    assert_non_null(inner2);
    assert_int_equal(inner2->base.type, TOKEN_WSH);

    const policy_node_multisig_t *inner3 =
        (policy_node_multisig_t *) r_policy_node(&inner2->script);
    assert_non_null(inner3);
    assert_int_equal(inner3->base.type, TOKEN_SORTEDMULTI);
    assert_int_equal(inner3->k, 5);
    assert_int_equal(inner3->n, 7);

    const policy_node_key_placeholder_t *key_placeholders =
        r_policy_node_key_placeholder(&inner3->key_placeholders);
    assert_non_null(key_placeholders);
    for (int i = 0; i < 7; i++) {
        assert_int_equal(key_placeholders[i].key_index, i);
        assert_int_equal(key_placeholders[i].num_first, 0);
        assert_int_equal(key_placeholders[i].num_second, 1);
    }
}

// ELIP 150: Valid Descriptor 1
static void test_parse_policy_map_blinded_xpub(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(0 <=
                PARSE_POLICY(
                    "ct(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5Ja"
                    "HWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,elpkh(@0/**))",
                    out,
                    sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_pubkey_t *mbk = (policy_node_blinding_pubkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_XPUB);
    static const uint8_t ref_pubkey[33] = {0x02, 0xd2, 0xb3, 0x69, 0x00, 0x39, 0x6c, 0x92, 0x82,
                                           0xfa, 0x14, 0x62, 0x85, 0x66, 0x58, 0x2f, 0x20, 0x6a,
                                           0x5d, 0xd0, 0xbc, 0xc8, 0xd5, 0xe8, 0x92, 0x61, 0x18,
                                           0x06, 0xca, 0xfb, 0x03, 0x01, 0xf0};
    assert_memory_equal(mbk->pubkey, ref_pubkey, sizeof(ref_pubkey));

    const policy_node_with_key_t *inner =
        (policy_node_with_key_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner);
    assert_int_equal(inner->base.type, TOKEN_PKH);

    const policy_node_key_placeholder_t *key_placeholder =
        r_policy_node_key_placeholder(&inner->key_placeholder);
    assert_non_null(key_placeholder);
    assert_int_equal(key_placeholder->key_index, 0);
    assert_int_equal(key_placeholder->num_first, 0);
    assert_int_equal(key_placeholder->num_second, 1);
}

// ELIP 150: Valid Descriptor 9
static void test_parse_policy_map_blinded_hex_pubkey(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(
        0 <=
        PARSE_POLICY(
            "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_pubkey_t *mbk = (policy_node_blinding_pubkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_HEX_PUB);
    static const uint8_t ref_pubkey[33] = {0x02, 0xdc, 0xe1, 0x60, 0x18, 0xbb, 0xbb, 0x8e, 0x36,
                                           0xde, 0x7b, 0x39, 0x4d, 0xf5, 0xb5, 0x16, 0x6e, 0x9a,
                                           0xdb, 0x74, 0x98, 0xbe, 0x7d, 0x88, 0x1a, 0x85, 0xa0,
                                           0x9a, 0xee, 0xcf, 0x76, 0xb6, 0x23};
    assert_memory_equal(mbk->pubkey, ref_pubkey, sizeof(ref_pubkey));

    const policy_node_with_key_t *inner =
        (policy_node_with_key_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner);
    assert_int_equal(inner->base.type, TOKEN_WPKH);

    const policy_node_key_placeholder_t *key_placeholder =
        r_policy_node_key_placeholder(&inner->key_placeholder);
    assert_non_null(key_placeholder);
    assert_int_equal(key_placeholder->key_index, 0);
    assert_int_equal(key_placeholder->num_first, 0);
    assert_int_equal(key_placeholder->num_second, 1);
}

// ELIP 150: View Descriptor
static void test_parse_policy_map_blinded_xprv(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(
        0 <=
        PARSE_POLICY(
            "ct("
            "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5qzmBaSpeMj5LdcsHaXJvM7"
            "iFEivPryRcL8irN7Na9p65UUb,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_privkey_t *mbk = (policy_node_blinding_privkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_XPRV);
    static const uint8_t ref_privkey[32] = {0x45, 0xb0, 0x6d, 0x52, 0x19, 0x7a, 0xf2, 0x5a,
                                            0xeb, 0x04, 0xd2, 0x4b, 0xa9, 0x3d, 0xbf, 0xfc,
                                            0xbb, 0x43, 0x76, 0x2d, 0xe2, 0xb5, 0x21, 0x3a,
                                            0x44, 0xf1, 0x20, 0x26, 0x5e, 0xd0, 0x73, 0x4c};
    assert_memory_equal(mbk->privkey, ref_privkey, sizeof(ref_privkey));

    const policy_node_with_key_t *inner =
        (policy_node_with_key_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner);
    assert_int_equal(inner->base.type, TOKEN_WPKH);

    const policy_node_key_placeholder_t *key_placeholder =
        r_policy_node_key_placeholder(&inner->key_placeholder);
    assert_non_null(key_placeholder);
    assert_int_equal(key_placeholder->key_index, 0);
    assert_int_equal(key_placeholder->num_first, 0);
    assert_int_equal(key_placeholder->num_second, 1);
}

// ELIP 150: View Descriptor 2
static void test_parse_policy_map_blinded_hex_privkey(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(
        0 <=
        PARSE_POLICY(
            "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_privkey_t *mbk = (policy_node_blinding_privkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_HEX_PRV);
    static const uint8_t ref_privkey[32] = {0xc2, 0x5d, 0xeb, 0x86, 0xfa, 0x11, 0xe4, 0x9d,
                                            0x65, 0x1d, 0x7e, 0xae, 0x27, 0xc2, 0x20, 0xef,
                                            0x93, 0x0f, 0xbd, 0x86, 0xea, 0x02, 0x3e, 0xeb,
                                            0xfa, 0x73, 0xe5, 0x48, 0x75, 0x64, 0x79, 0x63};
    assert_memory_equal(mbk->privkey, ref_privkey, sizeof(ref_privkey));

    const policy_node_with_key_t *inner =
        (policy_node_with_key_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner);
    assert_int_equal(inner->base.type, TOKEN_WPKH);

    const policy_node_key_placeholder_t *key_placeholder =
        r_policy_node_key_placeholder(&inner->key_placeholder);
    assert_non_null(key_placeholder);
    assert_int_equal(key_placeholder->key_index, 0);
    assert_int_equal(key_placeholder->num_first, 0);
    assert_int_equal(key_placeholder->num_second, 1);
}

static void test_parse_policy_map_empty_key_placeholder(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(
        0 <= PARSE_POLICY(
                 "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elwpkh(@0))",
                 out,
                 sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_privkey_t *mbk = (policy_node_blinding_privkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_HEX_PRV);
    static const uint8_t ref_privkey[32] = {0xc2, 0x5d, 0xeb, 0x86, 0xfa, 0x11, 0xe4, 0x9d,
                                            0x65, 0x1d, 0x7e, 0xae, 0x27, 0xc2, 0x20, 0xef,
                                            0x93, 0x0f, 0xbd, 0x86, 0xea, 0x02, 0x3e, 0xeb,
                                            0xfa, 0x73, 0xe5, 0x48, 0x75, 0x64, 0x79, 0x63};
    assert_memory_equal(mbk->privkey, ref_privkey, sizeof(ref_privkey));

    const policy_node_with_key_t *inner =
        (policy_node_with_key_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner);
    assert_int_equal(inner->base.type, TOKEN_WPKH);

    const policy_node_key_placeholder_t *key_placeholder =
        r_policy_node_key_placeholder(&inner->key_placeholder);
    assert_non_null(key_placeholder);
    assert_int_equal(key_placeholder->key_index, 0);
    assert_true(policy_is_key_placeholder_empty(key_placeholder));
}

// ELIP 151: Test vector 1
static void test_parse_policy_map_blinded_elip151(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];
    assert_true(0 <= PARSE_POLICY("ct(elip151,elwpkh(@0/<0;1>/*))", out, sizeof(out)));
    assert_int_equal(((const policy_node_t *) out)->type, TOKEN_CT);

    const policy_node_blinding_privkey_t *mbk = (policy_node_blinding_privkey_t *) r_policy_node(
        &((const policy_node_ct_t *) out)->mbk_script);
    assert_non_null(mbk);
    assert_int_equal(mbk->base.type, TOKEN_ELIP151);

    const policy_node_with_key_t *inner =
        (policy_node_with_key_t *) r_policy_node(&((const policy_node_ct_t *) out)->script);
    assert_non_null(inner);
    assert_int_equal(inner->base.type, TOKEN_WPKH);

    const policy_node_key_placeholder_t *key_placeholder =
        r_policy_node_key_placeholder(&inner->key_placeholder);
    assert_non_null(key_placeholder);
    assert_int_equal(key_placeholder->key_index, 0);
    assert_int_equal(key_placeholder->num_first, 0);
    assert_int_equal(key_placeholder->num_second, 1);
}

static void test_failures_blinded(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // Master blinding key script is required for ct() tag
    assert_true(0 > PARSE_POLICY("ct(wpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(,wpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(wpkh(@0/**),wpkh(@1/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(slip77(),wpkh(@0/**))", out, sizeof(out)));
}

static void test_failures_blinded_slip77(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // Correct descriptor
    assert_true(
        0 <=
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),"
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));

    // ct() must be top-level
    assert_true(0 >
                PARSE_POLICY(
                    "sh(ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141)"
                    ",wpkh(@0/**)))",
                    out,
                    sizeof(out)));

    // Broken format
    assert_true(
        0 >
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141)"
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141) "
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141,"
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),"
                     "wpkh(@0/**)",
                     out,
                     sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY("ct(slip77(x905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c14),"
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),slip77("
            "905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),wpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 > PARSE_POLICY(
                "ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141,"
                "905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),wpkh(@0/**))",
                out,
                sizeof(out)));

    // slip77() should not be used outside of ct() tag
    assert_true(
        0 > PARSE_POLICY("slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141)",
                         out,
                         sizeof(out)));
    assert_true(0 > PARSE_POLICY("slip77(@0/**)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("slip77(wpkh(@0/**))", out, sizeof(out)));

    // Master blinding key in HEX format must be exactly 64 characters
    assert_true(0 > PARSE_POLICY("ct(slip77(),wpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(slip77(9),wpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY(
                        "ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c14)"
                        ",wpkh(@0/**))",
                        out,
                        sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY("ct(slip77(905cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141A),"
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY("ct(slip77(9O5cfe33a3dfb37db513d1078c16bcfdf906ecd944c5ddd37fdfbcc5e619c141),"
                     "wpkh(@0/**))",
                     out,
                     sizeof(out)));
}

static void test_failures_blinded_xpub(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // Correct descriptor
    assert_true(0 <= PARSE_POLICY("ct("
                                  "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkr"
                                  "gZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,elpkh(@0/**))",
                                  out,
                                  sizeof(out)));

    // ct() must be top-level
    assert_true(0 > PARSE_POLICY("sh(ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,elpkh(@0/**)))",
                                 out,
                                 sizeof(out)));

    // Broken format
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcELelpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL elpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),elpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,elpkh(@0/**)",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,(elpkh(@0/**)))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,"
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,elpkh(@0/**))",
                                 out,
                                 sizeof(out)));

    // Extended public key must have valid format
    assert_true(0 > PARSE_POLICY("ct("
                                 "XPUB6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,elpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcE,elpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpubERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZ"
                                 "w4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,elpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrg"
                                 "Zw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEM,elpkh(@0/**))",
                                 out,
                                 sizeof(out)));
}

static void test_failures_blinded_xprv(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // Correct descriptor
    assert_true(0 <= PARSE_POLICY("ct("
                                  "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5"
                                  "qzmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,elwpkh(@0/**))",
                                  out,
                                  sizeof(out)));

    // ct() must be top-level
    assert_true(0 > PARSE_POLICY("sh(ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,elwpkh(@0/**)))",
                                 out,
                                 sizeof(out)));

    // Broken format
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUbelwpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb elwpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb),elwpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,elwpkh(@0/**)",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,(elwpkh(@0/**)))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,"
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,elwpkh(@0/**))",
                                 out,
                                 sizeof(out)));

    // Extended private key must have valid format
    assert_true(0 > PARSE_POLICY("ct("
                                 "XPRV9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,elwpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UU,elwpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprvs21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5qz"
                                 "mBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb,elwpkh(@0/**))",
                                 out,
                                 sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct("
                                 "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5q"
                                 "zmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUB,elwpkh(@0/**))",
                                 out,
                                 sizeof(out)));
}

static void test_failures_blinded_hex_pubkey(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // Correct descriptor
    assert_true(
        0 <=
        PARSE_POLICY(
            "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**))",
            out,
            sizeof(out)));

    // ct() must be top-level
    assert_true(
        0 > PARSE_POLICY("sh(ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,"
                         "elwpkh(@0/**)))",
                         out,
                         sizeof(out)));

    // Broken format
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623 elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 > PARSE_POLICY("ct((02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623),"
                         "elwpkh(@0/**))",
                         out,
                         sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**)",
            out,
            sizeof(out)));
    assert_true(
        0 > PARSE_POLICY("ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,("
                         "elwpkh(@0/**)))",
                         out,
                         sizeof(out)));
    assert_true(
        0 > PARSE_POLICY(
                "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,"
                "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**))",
                out,
                sizeof(out)));

    // Public key must have valid format and length
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(02Dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(02Lce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(00dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(04dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b62,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(02,elwpkh(@0/**))", out, sizeof(out)));
    assert_true(
        0 > PARSE_POLICY("ct(02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b62323,"
                         "elwpkh(@0/**))",
                         out,
                         sizeof(out)));
}

static void test_failures_blinded_hex_privkey(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // Correct descriptor
    assert_true(
        0 <=
        PARSE_POLICY(
            "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elwpkh(@0/**))",
            out,
            sizeof(out)));

    // ct() must be top-level
    assert_true(
        0 > PARSE_POLICY("sh(ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,"
                         "elwpkh(@0/**)))",
                         out,
                         sizeof(out)));

    // Broken format
    assert_true(
        0 > PARSE_POLICY(
                "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963elwpkh(@0/**))",
                out,
                sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963 elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct((c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963),elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 > PARSE_POLICY(
                "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elwpkh(@0/**)",
                out,
                sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,(elwpkh(@0/**)))",
            out,
            sizeof(out)));
    assert_true(
        0 > PARSE_POLICY(
                "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,"
                "c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elwpkh(@0/**))",
                out,
                sizeof(out)));

    // Private key must have valid format and length
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(C25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(C25DEB86FA11E49D651D7EAE27C220EF930FBD86EA023EEBFA73E54875647963,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(c25geb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e54875647963,elwpkh(@0/**))",
            out,
            sizeof(out)));
    assert_true(
        0 > PARSE_POLICY(
                "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e5487564796,elwpkh(@0/**))",
                out,
                sizeof(out)));
    assert_true(
        0 > PARSE_POLICY(
                "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e548756479,elwpkh(@0/**))",
                out,
                sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(c2,elwpkh(@0/**))", out, sizeof(out)));
    assert_true(
        0 >
        PARSE_POLICY(
            "ct(c25deb86fa11e49d651d7eae27c220ef930fbd86ea023eebfa73e5487564796363,elwpkh(@0/**))",
            out,
            sizeof(out)));
}

static void test_failures_blinded_elip151(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // Correct descriptor
    assert_true(0 <= PARSE_POLICY("ct(elip151,elwpkh(@0/**))", out, sizeof(out)));

    // ct() must be top-level
    assert_true(0 > PARSE_POLICY("sh(ct(elip151,elwpkh(@0/**)))", out, sizeof(out)));

    // Broken format
    assert_true(0 > PARSE_POLICY("ct(elip151elwpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(elip151 elwpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct((elip151),elwpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(elip151,elwpkh(@0/**)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(elip151,elwpkh(@0/**)))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(elip151,(elwpkh(@0/**)))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(elip151,elip151,elwpkh(@0/**))", out, sizeof(out)));

    // ELIP 151 tag must be valid
    assert_true(0 > PARSE_POLICY("ct(ELIP151,elwpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(Elip151,elwpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(elipp151,elwpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(eli151,elwpkh(@0/**))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("ct(elip15,elwpkh(@0/**))", out, sizeof(out)));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_liquid_get_script_confidential_address_segwit),
        cmocka_unit_test(test_liquid_get_script_confidential_address_p2sh),
        cmocka_unit_test(test_policy_unwrap_ct),
        cmocka_unit_test(test_policy_unwrap_blinded_ct),
        cmocka_unit_test(test_parse_policy_map_blinded_slip77_singlesig),
        cmocka_unit_test(test_parse_policy_map_blinded_slip77_multisig),
        cmocka_unit_test(test_parse_policy_map_blinded_xpub),
        cmocka_unit_test(test_parse_policy_map_blinded_hex_pubkey),
        cmocka_unit_test(test_parse_policy_map_blinded_xprv),
        cmocka_unit_test(test_parse_policy_map_blinded_hex_privkey),
        cmocka_unit_test(test_parse_policy_map_empty_key_placeholder),
        cmocka_unit_test(test_parse_policy_map_blinded_elip151),
        cmocka_unit_test(test_failures_blinded),
        cmocka_unit_test(test_failures_blinded_slip77),
        cmocka_unit_test(test_failures_blinded_xpub),
        cmocka_unit_test(test_failures_blinded_xprv),
        cmocka_unit_test(test_failures_blinded_hex_pubkey),
        cmocka_unit_test(test_failures_blinded_hex_privkey),
        cmocka_unit_test(test_failures_blinded_elip151),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
