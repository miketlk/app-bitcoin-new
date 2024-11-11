#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <cmocka.h>

#include "common/buffer.h"
#include "common/varint.h"
#include "liquid/liquid_asset_metadata.h"
#include "util.h"

typedef struct {
    uint8_t asset_tag[LIQUID_ASSET_TAG_LEN];
    const char *contract_str;
    uint8_t prevout_txid[SHA256_LEN];
    uint32_t prevout_index;
    asset_class_t asset_class;
    asset_info_t asset_info;
} asset_metadata_vector_t;

static const asset_metadata_vector_t asset_test_data[] = {
    // tether.to USDt (Tether USD)
    {.asset_tag = {0xce, 0x09, 0x1c, 0x99, 0x8b, 0x83, 0xc7, 0x8b, 0xb7, 0x1a, 0x63,
                   0x23, 0x13, 0xba, 0x37, 0x60, 0xf1, 0x76, 0x3d, 0x9c, 0xfc, 0xff,
                   0xae, 0x02, 0x25, 0x8f, 0xfa, 0x98, 0x65, 0xa3, 0x7b, 0xd2},
     .contract_str =
         "{\"entity\":{\"domain\":\"tether.to\"},"
         "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
         "\"name\":\"Tether USD\","
         "\"precision\":8,"
         "\"ticker\":\"USDt\","
         "\"version\":0}",
     .prevout_txid = {0x95, 0x96, 0xd2, 0x59, 0x27, 0x0e, 0xf5, 0xba, 0xc0, 0x02, 0x04,
                      0x35, 0xe6, 0xd8, 0x59, 0xae, 0xa6, 0x33, 0x40, 0x94, 0x83, 0xba,
                      0x64, 0xe2, 0x32, 0xb8, 0xba, 0x04, 0xce, 0x28, 0x86, 0x68},
     .asset_class = ACLASS_ASSET,
     .prevout_index = 0,
     .asset_info = {.ticker = "USDt", .decimals = 8}},
    // liquid.beer ASP (Atomic Swap Pint)
    {.asset_tag = {0x13, 0x31, 0x5b, 0x14, 0xd2, 0x40, 0xbd, 0xe1, 0xe7, 0x97, 0xd8,
                   0x39, 0x6c, 0xd5, 0x8f, 0x1e, 0x9f, 0xe9, 0xd0, 0xf4, 0x59, 0x29,
                   0x8a, 0x9c, 0x35, 0xa8, 0xfa, 0x44, 0xba, 0x87, 0x46, 0x2e},
     .contract_str =
         "{\"entity\":{\"domain\":\"liquid.beer\"},"
         "\"issuer_pubkey\":\"02436437ab5ecb6966b7dea1333fad14a658ae185d8ced00aa598af5997b55cd24\","
         "\"name\":\"Atomic Swap Pint\","
         "\"precision\":2,"
         "\"ticker\":\"ASP\","
         "\"version\":0}",
     .prevout_txid = {0xb7, 0xac, 0xa9, 0xbe, 0x7f, 0x31, 0x0a, 0xf0, 0xd9, 0xcd, 0xe3,
                      0x49, 0xbc, 0x7c, 0x5b, 0x8d, 0xd1, 0x38, 0xbb, 0xf0, 0x49, 0x9b,
                      0x28, 0xbf, 0x48, 0x2f, 0xd7, 0xe6, 0xd3, 0xe9, 0x0b, 0x66},
     .asset_class = ACLASS_ASSET,
     .prevout_index = 10,
     .asset_info = {.ticker = "ASP", .decimals = 2}},
    // assets.btse.com BTSE (BTSE Token)
    {.asset_tag = {0xb0, 0x0b, 0x0f, 0xf0, 0xb1, 0x1e, 0xbd, 0x47, 0xf7, 0xc6, 0xf5,
                   0x76, 0x14, 0xc0, 0x46, 0xdb, 0xbd, 0x20, 0x4e, 0x84, 0xbf, 0x01,
                   0x17, 0x8b, 0xaf, 0x2b, 0xe3, 0x71, 0x3a, 0x20, 0x6e, 0xb7},
     .contract_str =
         "{\"entity\":{\"domain\":\"assets.btse.com\"},"
         "\"issuer_pubkey\":\"032f7ef9146fe218d1322fb47767e73aced7b647ea103cb4ccf330ca363ffd3e9a\","
         "\"name\":\"BTSE Token\","
         "\"precision\":8,"
         "\"ticker\":\"BTSE\","
         "\"version\":0}",
     .prevout_txid = {0x8d, 0xec, 0xec, 0xf2, 0xb3, 0xcf, 0xa6, 0x1e, 0xeb, 0xb2, 0xac,
                      0x89, 0xaf, 0xb0, 0xd2, 0x25, 0xb9, 0x91, 0x73, 0x47, 0x02, 0xb1,
                      0x3c, 0xbb, 0x1e, 0xe7, 0x6e, 0x86, 0xb9, 0x57, 0xb7, 0x5b},
     .asset_class = ACLASS_ASSET,
     .prevout_index = 1,
     .asset_info = {.ticker = "BTSE", .decimals = 8}},
    // ELIP 100: example.com TEST (Testcoin)
    {.asset_tag = {0x48, 0xf8, 0x35, 0x62, 0x2f, 0x34, 0xe8, 0xfd, 0xc3, 0x13, 0xc9,
                   0x0d, 0x4a, 0x86, 0x59, 0xaa, 0x4a, 0xfe, 0x99, 0x3e, 0x32, 0xdc,
                   0xb0, 0x3a, 0xe6, 0xec, 0x9c, 0xcd, 0xc6, 0xfc, 0xbe, 0x18},
     .contract_str =
         "{\"entity\":{\"domain\":\"example.com\"},"
         "\"issuer_pubkey\":\"03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3\","
         "\"name\":\"Testcoin\","
         "\"precision\":2,"
         "\"ticker\":\"TEST\","
         "\"version\":0}",
     .prevout_txid = {0x35, 0x14, 0xa0, 0x7c, 0xf4, 0x81, 0x22, 0x72, 0xc2, 0x4a, 0x89,
                      0x8c, 0x48, 0x2f, 0x58, 0x7a, 0x51, 0x12, 0x6b, 0xee, 0xf8, 0xc9,
                      0xb7, 0x6a, 0x9e, 0x30, 0xbf, 0x41, 0xb0, 0xcb, 0xe5, 0x3c},
     .asset_class = ACLASS_ASSET,
     .prevout_index = 1,
     .asset_info = {.ticker = "TEST", .decimals = 2}},
    // ELIP 100: reissuance token for example.com TEST (Testcoin)
    {.asset_tag =
         {// Tag of the reissuance token
          0xd7, 0x39, 0x23, 0x40, 0x98, 0xf7, 0x71, 0x72, 0xcb, 0x22, 0xf0,
          0xde, 0x8a, 0xff, 0xd6, 0x82, 0x6d, 0x6b, 0x9d, 0x23, 0xd9, 0x7e,
          0x04, 0x57, 0x57, 0x64, 0x78, 0x6a, 0x5b, 0x00, 0x56, 0xe1},
     .contract_str =
         "{\"entity\":{\"domain\":\"example.com\"},"
         "\"issuer_pubkey\":\"03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3\","
         "\"name\":\"Testcoin\","
         "\"precision\":2,"
         "\"ticker\":\"TEST\","
         "\"version\":0}",
     .prevout_txid = {0x35, 0x14, 0xa0, 0x7c, 0xf4, 0x81, 0x22, 0x72, 0xc2, 0x4a, 0x89,
                      0x8c, 0x48, 0x2f, 0x58, 0x7a, 0x51, 0x12, 0x6b, 0xee, 0xf8, 0xc9,
                      0xb7, 0x6a, 0x9e, 0x30, 0xbf, 0x41, 0xb0, 0xcb, 0xe5, 0x3c},
     .asset_class = ACLASS_REISSUANCE_TOKEN_CONFIDENTIAL,
     .prevout_index = 1,
     .asset_info = {.ticker = "TEST", .decimals = 2}}};

extern bool asset_metadata_parser_init(asset_metadata_parser_context_t *ctx,
                                       asset_info_t *asset_info,
                                       asset_info_ext_t *ext_asset_info);
extern void asset_metadata_parser_process(asset_metadata_parser_context_t *ctx, buffer_t *data);
extern bool asset_metadata_parser_finalize(asset_metadata_parser_context_t *ctx,
                                           const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
                                           asset_class_t asset_class);

static asset_info_t *parse_metadata(buffer_t *data,
                                    const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
                                    asset_class_t asset_class) {
    asset_metadata_parser_context_t ctx;
    asset_info_t *asset_info = malloc(sizeof(asset_info_t));

    if (asset_info && asset_metadata_parser_init(&ctx, asset_info, NULL)) {
        asset_metadata_parser_process(&ctx, data);
        if (asset_metadata_parser_finalize(&ctx, asset_tag, asset_class)) {
            return asset_info;
        }
    }

    free(asset_info);
    return NULL;
}

static buffer_t *alloc_buffer(size_t size) {
    buffer_t *buffer = (buffer_t *) malloc(sizeof(buffer_t));
    if (buffer) {
        uint8_t *data = (uint8_t *) malloc(size);
        if (data) {
            *buffer = buffer_create(data, size);
            return buffer;
        }
        free(buffer);
    }

    return NULL;
}

static void free_buffer(buffer_t *buffer) {
    if (buffer) {
        if (buffer->ptr) {
            free(buffer->ptr);
        }
        free(buffer);
    }
}

static void free_s(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

static buffer_t *create_metadata(const asset_metadata_vector_t *vect) {
    size_t contract_len = strlen(vect->contract_str);
    size_t data_len = varint_size(contract_len) + contract_len + sizeof(vect->prevout_txid) + 4;

    // Reverse prevoutTxid before storing in asset metadata
    uint8_t prevout_txid_rev[SHA256_LEN];
    reverse_copy(prevout_txid_rev, vect->prevout_txid, sizeof(prevout_txid_rev));

    buffer_t *buffer = alloc_buffer(data_len);
    if (buffer) {
        bool ok = varint_write(buffer_get_cur(buffer), 0, contract_len) > 0 &&
                  buffer_seek_cur(buffer, varint_size(contract_len)) &&
                  buffer_write_bytes(buffer, (const uint8_t *) vect->contract_str, contract_len) &&
                  buffer_write_bytes(buffer, prevout_txid_rev, sizeof(prevout_txid_rev)) &&
                  buffer_write_u32(buffer, vect->prevout_index, LE) && buffer_seek_set(buffer, 0);

        if (ok) {
            return buffer;
        }
        free_buffer(buffer);
    }
    return NULL;
}

static void test_metadata_parser_valid(void **state) {
    int n_vectors = sizeof(asset_test_data) / sizeof(asset_test_data[0]);
    const asset_metadata_vector_t *p_vect = asset_test_data;

    for (int i = 0; i < n_vectors; ++i, p_vect++) {
        buffer_t *meta = create_metadata(p_vect);
        assert_non_null(meta);

        asset_info_t *info = parse_metadata(meta, p_vect->asset_tag, p_vect->asset_class);
        assert_non_null(info);

        if (info) {
            assert_string_equal(info->ticker, p_vect->asset_info.ticker);
            assert_int_equal((int) info->decimals, p_vect->asset_info.decimals);
        } else {
            assert_true(0);
        }
        free_s(info);
        free_buffer(meta);
    }
}

static void test_metadata_parser_invalid_truncated(void **state) {
    const asset_metadata_vector_t vect = asset_test_data[0];

    buffer_t *meta = create_metadata(&vect);
    assert_non_null(meta);

    // Remove one byte from the end
    --meta->size;

    // Test with truncated metadata
    {
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_null(info);
        free_s(info);
    }

    // Reset buffer and restore missing ending byte
    buffer_seek_set(meta, 0);
    ++meta->size;

    // Re-test with full metadata and ensure it parses correctly
    {
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_non_null(info);
        if (info) {
            assert_string_equal(info->ticker, vect.asset_info.ticker);
            assert_int_equal((int) info->decimals, vect.asset_info.decimals);
        } else {
            assert_true(0);
        }
        free_s(info);
    }

    free_buffer(meta);
}

static void test_metadata_parser_invalid_asset_tag(void **state) {
    asset_metadata_vector_t vect = asset_test_data[0];

    buffer_t *meta = create_metadata(&vect);
    assert_non_null(meta);

    // Corrupt first byte of asset tag and ensure parsing fails
    {
        vect.asset_tag[0] ^= 1;
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_null(info);
        free_s(info);
    }

    buffer_seek_set(meta, 0);  // Rewind metadata buffer

    // Restore asset tag by inverting the bit second time and re-test
    {
        vect.asset_tag[0] ^= 1;
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_non_null(info);
        if (info) {
            assert_string_equal(info->ticker, vect.asset_info.ticker);
            assert_int_equal((int) info->decimals, vect.asset_info.decimals);
        } else {
            assert_true(0);
        }
        free_s(info);
    }

    free_buffer(meta);
}

static void test_metadata_parser_invalid_contract(void **state) {
    // Create a valid test vector with a modifiable contract string
    char contract_str[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","
        "\"name\":\"Tether USD\","
        "\"precision\":8,"
        "\"ticker\":\"USDt\","
        "\"version\":0}";

    asset_metadata_vector_t vect = {
        .asset_tag = {0xce, 0x09, 0x1c, 0x99, 0x8b, 0x83, 0xc7, 0x8b, 0xb7, 0x1a, 0x63,
                      0x23, 0x13, 0xba, 0x37, 0x60, 0xf1, 0x76, 0x3d, 0x9c, 0xfc, 0xff,
                      0xae, 0x02, 0x25, 0x8f, 0xfa, 0x98, 0x65, 0xa3, 0x7b, 0xd2},
        .contract_str = contract_str,
        .prevout_txid = {0x95, 0x96, 0xd2, 0x59, 0x27, 0x0e, 0xf5, 0xba, 0xc0, 0x02, 0x04,
                         0x35, 0xe6, 0xd8, 0x59, 0xae, 0xa6, 0x33, 0x40, 0x94, 0x83, 0xba,
                         0x64, 0xe2, 0x32, 0xb8, 0xba, 0x04, 0xce, 0x28, 0x86, 0x68},
        .prevout_index = 0,
        .asset_info = {.ticker = "USDt", .decimals = 8}};

    // In the word "entity" inside the contract, replace first letter 'e' with capital 'E'
    char *entity = &contract_str[2];
    assert_true(entity[0] == 'e' && entity[1] == 'n' && entity[2] == 't' && entity[3] == 'i');
    entity[0] = 'E';

    // Ensure parsing fails with modified contract (produces different asset tag)
    {
        buffer_t *meta = create_metadata(&vect);
        assert_non_null(meta);
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_null(info);
        free_s(info);
        free_buffer(meta);
    }

    // Restore the "entity" word in its original writing
    entity[0] = 'e';

    // Re-test with corrected contract
    {
        buffer_t *meta = create_metadata(&vect);
        assert_non_null(meta);
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_non_null(info);
        if (info) {
            assert_string_equal(info->ticker, vect.asset_info.ticker);
            assert_int_equal((int) info->decimals, vect.asset_info.decimals);
        } else {
            assert_true(0);
        }
        free_s(info);
        free_buffer(meta);
    }
}

static void test_metadata_parser_invalid_prevout_txid(void **state) {
    asset_metadata_vector_t vect = asset_test_data[0];

    // Ensure parsing fails with modified prevoutTxid (produces different asset tag)
    vect.prevout_txid[0] ^= 1;
    {
        buffer_t *meta = create_metadata(&vect);
        assert_non_null(meta);
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_null(info);
        free_s(info);
        free_buffer(meta);
    }

    // Re-test with corrected prevoutTxid
    vect.prevout_txid[0] ^= 1;
    {
        buffer_t *meta = create_metadata(&vect);
        assert_non_null(meta);
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_non_null(info);
        if (info) {
            assert_string_equal(info->ticker, vect.asset_info.ticker);
            assert_int_equal((int) info->decimals, vect.asset_info.decimals);
        } else {
            assert_true(0);
        }
        free_s(info);
        free_buffer(meta);
    }
}

static void test_metadata_parser_invalid_prevout_index(void **state) {
    asset_metadata_vector_t vect = asset_test_data[0];

    // Ensure parsing fails with modified prevoutIndex (produces different asset tag)
    ++vect.prevout_index;
    {
        buffer_t *meta = create_metadata(&vect);
        assert_non_null(meta);
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_null(info);
        free_s(info);
        free_buffer(meta);
    }

    // Re-test with corrected prevoutIndex
    --vect.prevout_index;
    {
        buffer_t *meta = create_metadata(&vect);
        assert_non_null(meta);
        asset_info_t *info = parse_metadata(meta, vect.asset_tag, vect.asset_class);
        assert_non_null(info);
        if (info) {
            assert_string_equal(info->ticker, vect.asset_info.ticker);
            assert_int_equal((int) info->decimals, vect.asset_info.decimals);
        } else {
            assert_true(0);
        }
        free_s(info);
        free_buffer(meta);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_metadata_parser_valid),
        cmocka_unit_test(test_metadata_parser_invalid_truncated),
        cmocka_unit_test(test_metadata_parser_invalid_asset_tag),
        cmocka_unit_test(test_metadata_parser_invalid_contract),
        cmocka_unit_test(test_metadata_parser_invalid_prevout_txid),
        cmocka_unit_test(test_metadata_parser_invalid_prevout_index)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
