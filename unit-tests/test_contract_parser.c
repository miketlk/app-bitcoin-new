#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/buffer.h"
#include "liquid/contract_parser.h"

// Version bytes of Liquid regtest xpub
#define LIQUID_REGTEST_XPUB 0x043587CF
// Version bytes of Liquid regtest xprv
#define LIQUID_REGTEST_XPRV 0x04358394

// Mock BIP32_PUBKEY_VERSION and BIP32_PRIVKEY_VERSION macros with global variables
uint32_t BIP32_PUBKEY_VERSION = LIQUID_REGTEST_XPUB;
uint32_t BIP32_PRIVKEY_VERSION = LIQUID_REGTEST_XPRV;

typedef struct {
    const char *contract_str;
    uint8_t hash[SHA256_LEN];
    asset_info_ext_t asset;
} contract_test_data_t;

typedef struct {
    uint8_t hash[SHA256_LEN];
    asset_info_ext_t asset;
} parser_outputs_t;

static const contract_test_data_t contract_test_data[] = {
    // tether.to USDt (Tether USD)
    {.contract_str =
         "{\"entity\":{\"domain\":\"tether.to\"},"
         "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
         "\"name\":\"Tether USD\","
         "\"precision\":8,"
         "\"ticker\":\"USDt\","
         "\"version\":0}",
     .hash = {0x3c, 0x7f, 0x0a, 0x53, 0xc2, 0xff, 0x5b, 0x99, 0x59, 0x06, 0x20,
              0xd7, 0xf6, 0x60, 0x4a, 0x7a, 0x3a, 0x7b, 0xfb, 0xaa, 0xa6, 0xaa,
              0x61, 0xf7, 0xbf, 0xc7, 0x83, 0x3c, 0xa0, 0x3c, 0xde, 0x82},
     .asset = {.info = {.ticker = "USDt", .decimals = 8},
               .name = "Tether USD",
               .domain = "tether.to"}},
    // liquid.beer ASP (Atomic Swap Pint)
    {.contract_str =
         "{\"entity\":{\"domain\":\"liquid.beer\"},"
         "\"issuer_pubkey\":\"02436437ab5ecb6966b7dea1333fad14a658ae185d8ced00aa598af5997b55cd24\","
         "\"name\":\"Atomic Swap Pint\","
         "\"precision\":2,"
         "\"ticker\":\"ASP\","
         "\"version\":0}",
     .hash = {0x0b, 0xba, 0x2b, 0x02, 0xe5, 0xa9, 0x39, 0xf3, 0xcb, 0xdc, 0x87,
              0xc7, 0x0b, 0xa0, 0x9b, 0x3d, 0x64, 0xeb, 0x43, 0x4e, 0xef, 0x25,
              0xb3, 0xf3, 0x14, 0xaf, 0xcf, 0x0c, 0x0a, 0xd7, 0x07, 0x3f},
     .asset = {.info = {.ticker = "ASP", .decimals = 2},
               .name = "Atomic Swap Pint",
               .domain = "liquid.beer"}},
    // ciao.it TTT
    {.contract_str =
         "{\"entity\":{\"domain\":\"ciao.it\"},"
         "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
         "\"name\":\"name\","
         "\"precision\":8,"
         "\"ticker\":\"TTT\","
         "\"version\":0}",
     .hash = {0x25, 0x2a, 0x3a, 0xb4, 0x07, 0x19, 0x58, 0x3c, 0xaa, 0x5e, 0x88,
              0x5c, 0x27, 0xe0, 0xa2, 0xa3, 0xe6, 0x2e, 0x32, 0xe7, 0x1d, 0xad,
              0xf0, 0xb6, 0x50, 0xf8, 0xca, 0xee, 0x55, 0x87, 0x81, 0x53},
     .asset = {.info = {.ticker = "TTT", .decimals = 8}, .name = "name", .domain = "ciao.it"}},
    // ELIP 100: example.com TEST (Testcoin)
    {.contract_str =
         "{\"entity\":{\"domain\":\"example.com\"},"
         "\"issuer_pubkey\":\"03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3\","
         "\"name\":\"Testcoin\","
         "\"precision\":2,"
         "\"ticker\":\"TEST\","
         "\"version\":0}",
     .hash = {0xd4, 0x0c, 0x36, 0x4f, 0x8b, 0x94, 0x3e, 0x43, 0x4f, 0x68, 0x27,
              0x55, 0x6a, 0x5a, 0x04, 0xb3, 0x37, 0xbc, 0x62, 0x7b, 0x90, 0x4a,
              0x04, 0x39, 0x5f, 0xee, 0xd0, 0x6d, 0x13, 0xae, 0x30, 0x37},
     .asset = {.info = {.ticker = "TEST", .decimals = 2},
               .name = "Testcoin",
               .domain = "example.com"}},
};

static bool parse_contract(const char *contract, parser_outputs_t *outs) {
    contract_parser_context_t ctx;
    buffer_t contract_buffer = buffer_create((void *) contract, strlen(contract));

    if (contract_parser_init(&ctx, NULL, &outs->asset)) {
        contract_parser_process(&ctx, &contract_buffer);
        return contract_parser_finalize(&ctx, outs->hash);
    }
    return false;
}

static bool parse_contract_basic_info(const char *contract, parser_outputs_t *outs) {
    contract_parser_context_t ctx;
    buffer_t contract_buffer = buffer_create((void *) contract, strlen(contract));

    if (contract_parser_init(&ctx, &outs->asset.info, NULL)) {
        contract_parser_process(&ctx, &contract_buffer);
        return contract_parser_finalize(&ctx, outs->hash);
    }
    return false;
}

static void test_contract_parser_valid(void **state) {
    (void) state;

    int n_vectors = sizeof(contract_test_data) / sizeof(contract_test_data[0]);
    const contract_test_data_t *p_vect = contract_test_data;
    parser_outputs_t outs;

    for (int i = 0; i < n_vectors; ++i, p_vect++) {
        memset(&outs, 0xee, sizeof(outs));
        bool res = parse_contract(p_vect->contract_str, &outs);
        assert_true(res);
        assert_memory_equal(outs.hash, p_vect->hash, sizeof(outs.hash));
        assert_string_equal(outs.asset.info.ticker, p_vect->asset.info.ticker);
        assert_int_equal((int) outs.asset.info.decimals, (int) p_vect->asset.info.decimals);
        assert_string_equal(outs.asset.name, p_vect->asset.name);
        assert_string_equal(outs.asset.domain, p_vect->asset.domain);
    }
}

static void test_contract_parser_basic_info_only(void **state) {
    (void) state;

    int n_vectors = sizeof(contract_test_data) / sizeof(contract_test_data[0]);
    const contract_test_data_t *p_vect = contract_test_data;
    parser_outputs_t outs;

    for (int i = 0; i < n_vectors; ++i, p_vect++) {
        memset(&outs, 0xee, sizeof(outs));
        bool res = parse_contract_basic_info(p_vect->contract_str, &outs);
        assert_true(res);
        assert_memory_equal(outs.hash, p_vect->hash, sizeof(outs.hash));
        assert_string_equal(outs.asset.info.ticker, p_vect->asset.info.ticker);
        assert_int_equal((int) outs.asset.info.decimals, (int) p_vect->asset.info.decimals);

        // Check that remaining bytes of extended asset information are unchanged
        const uint8_t *p_ext_byte = (const uint8_t *) &outs.asset + sizeof(outs.asset.info);
        for (size_t j = 0; j < sizeof(outs.asset) - sizeof(outs.asset.info); ++j) {
            assert_int_equal((int) *p_ext_byte, 0xee);
            ++p_ext_byte;
        }
    }
}

static void test_contract_parser_missing_fields(void **state) {
    (void) state;
    static const char complete[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
        "\"name\":\"Tether USD\","
        "\"precision\":8,"
        "\"ticker\":\"USDt\","
        "\"version\":0}";

    static const char missing_precision[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
        "\"name\":\"Tether USD\","
        "\"ticker\":\"USDt\","
        "\"version\":0}";

    static const char missing_name[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
        "\"precision\":8,"
        "\"ticker\":\"USDt\","
        "\"version\":0}";

    parser_outputs_t outs;
    assert_true(parse_contract(complete, &outs));
    assert_false(parse_contract(missing_precision, &outs));
    assert_false(parse_contract(missing_name, &outs));
}

static void test_contract_parser_skip_nested_arrays(void **state) {
    (void) state;

    static const char contract[] =
        "{\"entity\":{\"domain\":\"liquid.beer\"},"
        "\"issuer_pubkey\":\"02436437ab5ecb6966b7dea1333fad14a658ae185d8ced00aa598af5997b55cd24\","
        "\"name\":\"Atomic Swap Pint\","
        "\"arr\":[1,2,3,[\"a\",\"b\",[\"x\",\"y\",\"z\"],[],\"c\"],4,[]],"
        "\"precision\":2,"
        "\"ticker\":\"ASP\","
        "\"version\":0}";

    parser_outputs_t outs;
    assert_true(parse_contract(contract, &outs));
    assert_string_equal(outs.asset.info.ticker, "ASP");
    assert_int_equal((int) outs.asset.info.decimals, 2);
    assert_string_equal(outs.asset.name, "Atomic Swap Pint");
    assert_string_equal(outs.asset.domain, "liquid.beer");
}

static void test_contract_parser_skip_nested_objects(void **state) {
    (void) state;

    static const char contract[] =
        "{\"entity\":{\"domain\":\"liquid.beer\"},"
        "\"issuer_pubkey\":\"02436437ab5ecb6966b7dea1333fad14a658ae185d8ced00aa598af5997b55cd24\","
        "\"name\":\"Atomic Swap Pint\","
        "\"precision\":2,"
        "\"obj\":{\"a\":1,\"b\":{\"x\":{\"xx\":true},\"y\"},\"c\":{}},"
        "\"ticker\":\"ASP\","
        "\"version\":0}";

    parser_outputs_t outs;
    assert_true(parse_contract(contract, &outs));
    assert_string_equal(outs.asset.info.ticker, "ASP");
    assert_int_equal((int) outs.asset.info.decimals, 2);
    assert_string_equal(outs.asset.name, "Atomic Swap Pint");
    assert_string_equal(outs.asset.domain, "liquid.beer");
}

static void test_contract_parser_no_ticker(void **state) {
    (void) state;

    static const char contract[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
        "\"name\":\"Tether USD\","
        "\"precision\":8,"
        "\"version\":0}";

    parser_outputs_t outs;
    assert_true(parse_contract(contract, &outs));
    assert_string_equal(outs.asset.info.ticker, UNKNOWN_ASSET_TICKER);
    assert_int_equal((int) outs.asset.info.decimals, 8);
    assert_string_equal(outs.asset.name, "Tether USD");
    assert_string_equal(outs.asset.domain, "tether.to");
}

static void test_contract_parser_limits(void **state) {
    (void) state;
    parser_outputs_t outs;

    {  // Maximum values
        static const char contract[] =
            "{\"entity\":{\"domain\":\"abcdefghijklmnopqrstuvwxyz.abcd\"},"
            "\"name\":\"Abcdefghijklmnopqrstuvwxyzabcde\","
            "\"precision\":19,"
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_true(parse_contract(contract, &outs));
        assert_string_equal(outs.asset.info.ticker, "ABCDEFGHIJ");
        assert_int_equal((int) outs.asset.info.decimals, 19);
        assert_string_equal(outs.asset.name, "Abcdefghijklmnopqrstuvwxyzabcde");
        assert_string_equal(outs.asset.domain, "abcdefghijklmnopqrstuvwxyz.abcd");
    }

    {  // Minimum values
        static const char contract[] =
            "{\"entity\":{\"domain\":\"a\"},"
            "\"name\":\"A\","
            "\"precision\":0,"
            "\"ticker\":\"A\"}";
        assert_true(parse_contract(contract, &outs));
        assert_string_equal(outs.asset.info.ticker, "A");
        assert_int_equal((int) outs.asset.info.decimals, 0);
        assert_string_equal(outs.asset.name, "A");
        assert_string_equal(outs.asset.domain, "a");
    }

    {  // Precision higher than allowed
        static const char contract[] =
            "{\"precision\":20,"
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }

    {  // Precision lower than allowed
        static const char contract[] =
            "{\"precision\":-1,"
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }
}

static void test_contract_parser_corrupted(void **state) {
    (void) state;
    parser_outputs_t outs;

    {  // Missing opening curly bracket
        static const char contract[] =
            "\"precision\":19,"
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }

    {  // Missing closing curly bracket
        static const char contract[] =
            "{\"precision\":19,"
            "\"ticker\":\"ABCDEFGHIJ\"";
        assert_false(parse_contract(contract, &outs));
    }

    {  // Missing comma
        static const char contract[] =
            "{\"precision\":19"
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }

    {  // Unexpected whitespace
        static const char contract[] =
            "{ \"precision\":19,"
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_contract_parser_valid),
        cmocka_unit_test(test_contract_parser_basic_info_only),
        cmocka_unit_test(test_contract_parser_missing_fields),
        cmocka_unit_test(test_contract_parser_skip_nested_arrays),
        cmocka_unit_test(test_contract_parser_skip_nested_objects),
        cmocka_unit_test(test_contract_parser_no_ticker),
        cmocka_unit_test(test_contract_parser_limits),
        cmocka_unit_test(test_contract_parser_corrupted),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
