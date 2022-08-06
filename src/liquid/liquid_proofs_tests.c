#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "cx_stubs.h"
#include "lcx_math.h"
#include "cx_errors.h"
#include "ox_ec.h"

#include "write.h"
#include "crypto.h"
#include "liquid.h"
#include "liquid_proofs.h"
#include "tests.h"

#ifdef IMPLEMENT_ON_DEVICE_TESTS

extern bool secp256k1_scalar_check_overflow(const uint8_t a[static 32]);
extern bool secp256k1_fe_is_quad_var(const uint8_t a[static 32]);

typedef struct {
    uint64_t value;
    uint8_t commit[33];
    uint8_t proof[73];
    uint16_t proof_len;
} value_proof_test_data_t;

static const value_proof_test_data_t value_proof_test_data[] = {
  { // This vector is taken from libsecp256k1 tests
    .value = UINT64_MAX,
    .commit = {
        0x08,
        0xc7, 0xea, 0x40, 0x7d, 0x26, 0x38, 0xa2, 0x99, 0xb9, 0x40, 0x22, 0x78, 0x17, 0x57, 0x65, 0xb3,
        0x36, 0x82, 0x18, 0x42, 0xc5, 0x57, 0x04, 0x5e, 0x58, 0x5e, 0xf6, 0x40, 0x8b, 0x24, 0x73, 0x10
    },
    .proof = {
        0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdc, 0x7d, 0x0b, 0x79, 0x0e, 0xaf, 0x41,
        0xa5, 0x8e, 0x9b, 0x0c, 0x5b, 0xa3, 0xee, 0x7d, 0xfd, 0x3d, 0x6b, 0xf3, 0xac, 0x04, 0x8a, 0x43,
        0x75, 0xb0, 0xb7, 0x0e, 0x92, 0xd7, 0xdf, 0xf0, 0x76, 0xc4, 0xa5, 0xb6, 0x2f, 0xf1, 0xb5, 0xfb,
        0xb4, 0xb6, 0x29, 0xea, 0x34, 0x9b, 0x16, 0x30, 0x0d, 0x06, 0xf1, 0xb4, 0x3f, 0x0d, 0x73, 0x59,
        0x75, 0xbf, 0x5d, 0x19, 0x59, 0xef, 0x11, 0xf0, 0xbf
    },
    .proof_len = 73
  },
  {
    .value = 0LLU,
    .commit = {
        0x09, 0x55, 0x5d, 0xad, 0xed, 0x78, 0x82, 0xfe, 0xd8, 0x28, 0x75, 0xd0, 0xff, 0xb0, 0x33, 0xeb,
        0x71, 0x90, 0x37, 0x98, 0x40, 0xe1, 0x8d, 0x18, 0x9c, 0x17, 0x4d, 0xd4, 0xc3, 0x8b, 0xfd, 0x18,
        0x72
    },
    .proof = {
        0x00, 0x9c, 0xe1, 0x98, 0x49, 0xeb, 0xcb, 0xcd, 0xe6, 0xfe, 0x4d, 0x44, 0xf8, 0xea, 0x22, 0x14,
        0xe7, 0x77, 0x7f, 0x56, 0x7b, 0x98, 0xf5, 0xf9, 0x0d, 0xea, 0x06, 0x78, 0xf9, 0x15, 0xc2, 0xc2,
        0xbf, 0x5e, 0x1e, 0x3d, 0xd1, 0x13, 0xd1, 0xea, 0x6c, 0xd2, 0xab, 0xe7, 0xa6, 0xd6, 0xd1, 0xf2,
        0x9f, 0x91, 0x29, 0x84, 0x30, 0x47, 0x23, 0x8f, 0x90, 0xa1, 0x0a, 0x0c, 0xc4, 0x3e, 0x32, 0xda,
        0x6e
    },
    .proof_len = 65
  },
  {
    .value = 1LLU,
    .commit = {
        0x09, 0x75, 0x0e, 0x3a, 0x08, 0xad, 0x24, 0xd4, 0x43, 0x04, 0x60, 0x5e, 0xc8, 0x0e, 0x66, 0x68,
        0x4c, 0x3a, 0x48, 0x97, 0xe1, 0x49, 0x8e, 0xdd, 0x52, 0xf3, 0x0a, 0xbc, 0x3c, 0xab, 0xb3, 0xcc,
        0xdc
    },
    .proof = {
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xb8, 0x3e, 0x40, 0x29, 0xaf, 0xfc, 0x9a,
        0xf1, 0x32, 0x87, 0xf0, 0x89, 0x57, 0x1d, 0x77, 0x24, 0x00, 0x10, 0xb0, 0x42, 0x6f, 0x2a, 0x1d,
        0x77, 0x7e, 0xf4, 0xfb, 0x1f, 0x51, 0x31, 0x14, 0xab, 0xdc, 0x35, 0xe7, 0xa0, 0xcd, 0x79, 0xca,
        0x0b, 0xdd, 0xfd, 0xd3, 0x61, 0xc6, 0xe5, 0x83, 0x1d, 0xea, 0x18, 0x49, 0xb2, 0x38, 0x5c, 0xd9,
        0x41, 0xa2, 0xa5, 0x79, 0x21, 0x67, 0x0a, 0xc9, 0xe1
    },
    .proof_len = 73
  },
  {
    .value = 2LLU,
    .commit = {
        0x08, 0x4a, 0x7f, 0xe3, 0x6f, 0x47, 0xff, 0x0a, 0x02, 0x9d, 0x74, 0x91, 0x61, 0xa8, 0x6a, 0xc8,
        0xf9, 0x2c, 0x7a, 0x24, 0xf1, 0xe9, 0xd2, 0x25, 0x7c, 0xfc, 0x61, 0xcb, 0x56, 0xa4, 0x09, 0x91,
        0xbb
    },
    .proof = {
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xd6, 0x78, 0x9f, 0xbe, 0xe1, 0x39, 0x20,
        0xe8, 0x65, 0xbb, 0x73, 0xfd, 0x93, 0x70, 0x32, 0x15, 0xed, 0x0a, 0xc1, 0x13, 0x36, 0x13, 0xd1,
        0xd5, 0x10, 0x3a, 0x95, 0xc9, 0x8f, 0x7e, 0x9b, 0xbd, 0x70, 0xea, 0x4e, 0xed, 0x56, 0x1d, 0x9e,
        0xd6, 0x6f, 0x7d, 0x96, 0xcc, 0x7b, 0x68, 0x5a, 0x50, 0x5d, 0x87, 0xe6, 0xae, 0x8e, 0x0a, 0x04,
        0x62, 0x4e, 0x7c, 0x10, 0xba, 0x84, 0xdf, 0x6e, 0x36
    },
    .proof_len = 73
  },
  {
    .value = 18446744073709551614LLU,
    .commit = {
        0x08, 0x40, 0x2b, 0x67, 0x97, 0xf3, 0x5f, 0x81, 0xc0, 0xbb, 0x81, 0xf5, 0x13, 0x35, 0x3a, 0xd6,
        0x1d, 0xde, 0x73, 0x8c, 0x77, 0x86, 0xbd, 0x7d, 0xdb, 0xb2, 0xb8, 0x55, 0xfd, 0x84, 0x98, 0x21,
        0xfd
    },
    .proof = {
        0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x2d, 0x4e, 0x97, 0x60, 0x61, 0x13, 0xb4,
        0xc9, 0x62, 0x93, 0x2b, 0x2e, 0x82, 0x68, 0x8d, 0x7a, 0x96, 0x19, 0x03, 0x7c, 0x3d, 0x6c, 0x3d,
        0xb4, 0x53, 0xdb, 0x9e, 0x86, 0x4e, 0xe0, 0x61, 0xc3, 0x6e, 0x9f, 0xe2, 0x34, 0xa4, 0x56, 0x0f,
        0x84, 0xad, 0xcc, 0xdc, 0x63, 0x22, 0xb7, 0x58, 0x08, 0x64, 0xe3, 0x1b, 0x37, 0x39, 0x14, 0x02,
        0x1e, 0xa2, 0xfa, 0xb3, 0xc7, 0x2f, 0xc9, 0xc2, 0x12
    },
    .proof_len = 73
  },
  {
    .value = 18446744073709551615LLU,
    .commit = {
        0x09, 0x45, 0xbf, 0xcb, 0xa5, 0x73, 0x70, 0x80, 0x9d, 0x4b, 0xdc, 0xae, 0xdb, 0xd7, 0xca, 0x0b,
        0xed, 0xf8, 0x88, 0xeb, 0xa4, 0xc5, 0x96, 0x5d, 0x7a, 0xd6, 0x7c, 0xfb, 0x0c, 0x83, 0xee, 0x0c,
        0xf3
    },
    .proof = {
        0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x45, 0x7b, 0x81, 0x80, 0xf3, 0xdc, 0xe4,
        0xb3, 0x8e, 0x20, 0x06, 0xa2, 0x1f, 0x50, 0xd5, 0x82, 0x48, 0x8c, 0x91, 0x01, 0xef, 0x26, 0x5c,
        0x91, 0xac, 0x8b, 0x8c, 0x97, 0x62, 0x77, 0x36, 0x9f, 0xb1, 0xbc, 0x66, 0x9e, 0xc4, 0x27, 0x2f,
        0x87, 0x59, 0x93, 0x93, 0x9b, 0xcb, 0x6c, 0xed, 0xd6, 0xd2, 0xf9, 0xff, 0x91, 0xe4, 0x83, 0x78,
        0x92, 0x8d, 0x48, 0xb4, 0x04, 0xe9, 0xa1, 0xfa, 0xd0
    },
    .proof_len = 73
  },
  {
    .value = 5064486629509554901LLU,
    .commit = {
        0x09, 0xbb, 0x6b, 0x8a, 0x4e, 0x25, 0x07, 0xf5, 0xd9, 0x04, 0x3a, 0x0e, 0x13, 0xad, 0xc2, 0x8c,
        0xac, 0xb7, 0x90, 0x9e, 0x8e, 0xdb, 0x62, 0x2e, 0x69, 0x8a, 0x74, 0x61, 0xfe, 0x51, 0x01, 0xc3,
        0x5f
    },
    .proof = {
        0x20, 0x46, 0x48, 0xab, 0xc1, 0xb9, 0xa1, 0xe2, 0xd5, 0x3c, 0x62, 0xe4, 0xb3, 0x74, 0xc8, 0xf3,
        0x73, 0x70, 0xe8, 0xc6, 0x9f, 0x83, 0x53, 0x83, 0xa4, 0x45, 0x0b, 0xee, 0x24, 0x34, 0xda, 0x28,
        0xbf, 0x5c, 0x7c, 0x0c, 0x55, 0x5a, 0x33, 0xb6, 0x73, 0x73, 0x9c, 0xc0, 0x89, 0x82, 0x74, 0x7d,
        0x76, 0xc4, 0xaf, 0x58, 0xd8, 0xe7, 0xa4, 0x3d, 0x1b, 0x48, 0x03, 0xb4, 0xfd, 0xaa, 0xc9, 0x6f,
        0xc1, 0xff, 0xa8, 0xf2, 0x01, 0xeb, 0x54, 0x0c, 0x85
    },
    .proof_len = 73
  },
  {
    .value = 14523218365401597110LLU,
    .commit = {
        0x08, 0xa0, 0xa7, 0x14, 0xeb, 0x6d, 0x23, 0x45, 0x51, 0x5b, 0x0a, 0x42, 0x1c, 0xd0, 0x49, 0x77,
        0x18, 0xf5, 0xfa, 0x07, 0x6f, 0x9a, 0xa0, 0x52, 0xf4, 0xc6, 0xf7, 0xd1, 0x4a, 0x89, 0x8c, 0x6b,
        0x6b
    },
    .proof = {
        0x20, 0xc9, 0x8c, 0xd6, 0x27, 0xf1, 0x31, 0x04, 0xb6, 0x8a, 0x28, 0x00, 0x35, 0xe0, 0x51, 0xe4,
        0xf0, 0xf3, 0xc6, 0x4e, 0xa1, 0x06, 0xe5, 0xde, 0x51, 0x4d, 0x62, 0x22, 0x43, 0x41, 0xeb, 0x62,
        0x98, 0xfe, 0x26, 0x07, 0x48, 0x06, 0x29, 0x4e, 0xe8, 0x68, 0x2a, 0x14, 0x59, 0x68, 0x3e, 0x4c,
        0x5f, 0xcb, 0x53, 0x17, 0x25, 0xee, 0x9a, 0x66, 0xbc, 0x45, 0x08, 0xc0, 0x88, 0xbd, 0xc5, 0x67,
        0xfc, 0xef, 0x42, 0x84, 0x69, 0x07, 0x36, 0x97, 0xb4
    },
    .proof_len = 73
  },
  {
    .value = 13047866814353592094LLU,
    .commit = {
        0x08, 0xdd, 0x2d, 0xd9, 0x0b, 0x30, 0x70, 0x1d, 0x8e, 0xd0, 0x81, 0xdf, 0xa0, 0x1b, 0x34, 0x79,
        0x20, 0xf3, 0x36, 0x99, 0xd9, 0xcb, 0x4b, 0x47, 0x1d, 0x80, 0xfe, 0xd6, 0xdb, 0xdb, 0xda, 0xd3,
        0xe6
    },
    .proof = {
        0x20, 0xb5, 0x13, 0x55, 0xbc, 0xb2, 0x27, 0x4f, 0x1e, 0x9e, 0x41, 0x06, 0x4a, 0xd3, 0xb5, 0xb2,
        0x2e, 0xf3, 0xfc, 0x81, 0x7e, 0xbe, 0x9e, 0x93, 0xd8, 0xe5, 0xa0, 0x1c, 0x8d, 0x74, 0xa0, 0x67,
        0x22, 0x63, 0xb8, 0xd3, 0x42, 0xa9, 0x58, 0xcc, 0x9d, 0x84, 0x95, 0x5f, 0x60, 0x8c, 0x15, 0xc4,
        0xa9, 0xb6, 0xb3, 0xcb, 0xc4, 0xc3, 0xbb, 0xde, 0x2c, 0x24, 0x5c, 0xf2, 0xf6, 0x99, 0x4d, 0x57,
        0x7e, 0x8b, 0x89, 0x53, 0x8b, 0x64, 0x09, 0xdf, 0xf3
    },
    .proof_len = 73
  },
  {
    .value = 701077867393263738LLU,
    .commit = {
        0x08, 0x78, 0x4c, 0xbd, 0x3b, 0x8a, 0x1e, 0x76, 0xd0, 0x16, 0xa5, 0x08, 0x93, 0x6c, 0xa4, 0xca,
        0xe8, 0x19, 0x6c, 0x0d, 0x2d, 0xf1, 0xee, 0xad, 0xfe, 0xfd, 0x8b, 0x43, 0xfc, 0xe5, 0x38, 0x6f,
        0xac
    },
    .proof = {
        0x20, 0x09, 0xba, 0xba, 0x9b, 0x1d, 0xdd, 0x28, 0x7a, 0x9c, 0xa9, 0xb5, 0x3e, 0xdb, 0x5b, 0xb0,
        0x5c, 0x0b, 0x1d, 0xe0, 0xcd, 0xcb, 0x9a, 0xc7, 0xc4, 0x99, 0x33, 0x6a, 0xaa, 0x67, 0x95, 0x29,
        0xfb, 0xca, 0xe7, 0x26, 0x87, 0x52, 0xb6, 0x18, 0xf3, 0xac, 0x83, 0xbd, 0xd5, 0x69, 0x3f, 0x70,
        0x03, 0x10, 0xc7, 0x0a, 0x99, 0xfe, 0x2b, 0xb6, 0xd1, 0x04, 0x8f, 0x24, 0x23, 0x37, 0x96, 0x25,
        0x66, 0x72, 0xaf, 0x5a, 0x69, 0x0f, 0xd5, 0x79, 0xa1
    },
    .proof_len = 73
  },
  {
    .value = 381144876043720517LLU,
    .commit = {
        0x08, 0x80, 0xf9, 0x55, 0x54, 0x23, 0xa0, 0x4b, 0x09, 0x24, 0x08, 0x47, 0x83, 0x77, 0xb7, 0x8d,
        0x62, 0xa7, 0x34, 0x0e, 0xcc, 0x8e, 0xa3, 0x8e, 0x5c, 0x1d, 0x56, 0xd2, 0xbe, 0x24, 0x02, 0x0a,
        0x72
    },
    .proof = {
        0x20, 0x05, 0x4a, 0x19, 0x3e, 0xd0, 0x8b, 0xd7, 0x45, 0x8f, 0xf1, 0x1f, 0x86, 0xb9, 0xea, 0x6c,
        0xbc, 0xc0, 0x1b, 0x43, 0x85, 0x44, 0x24, 0x4a, 0x82, 0xbe, 0xee, 0x32, 0x3a, 0x2e, 0x49, 0xa2,
        0x4d, 0xa6, 0x2e, 0x8c, 0x0c, 0x54, 0xd6, 0x45, 0x34, 0x39, 0xae, 0xfd, 0x48, 0x82, 0x63, 0xb5,
        0x97, 0xdb, 0x73, 0xb2, 0x4e, 0x54, 0xe2, 0xef, 0xf7, 0x93, 0x42, 0x75, 0xd9, 0x3c, 0x48, 0xca,
        0xa3, 0xd5, 0xaf, 0xd2, 0x7a, 0xfe, 0x94, 0xc4, 0xef
    },
    .proof_len = 73
  }
};

static void test_rangeproof_single_value(test_ctx_t *test_ctx) {
    int n_vectors = sizeof(value_proof_test_data) / sizeof(value_proof_test_data[0]);
    const value_proof_test_data_t *p_vect = value_proof_test_data;
    uint8_t wrong_commit[33];
    bool res;

    for(int i = 0; i < n_vectors; ++i, p_vect++) {
        // Test with correct parameters
        res = liquid_rangeproof_verify_value(p_vect->proof,
                                             p_vect->proof_len,
                                             p_vect->value,
                                             p_vect->commit,
                                             sizeof(p_vect->commit),
                                             secp256k1_generator_h);
        TEST_ASSERT(res);

        // Test with wrong value
        res = liquid_rangeproof_verify_value(p_vect->proof,
                                             p_vect->proof_len,
                                             p_vect->value ^ (1 << (i & 63)), /* corrupt */
                                             p_vect->commit,
                                             sizeof(p_vect->commit),
                                             secp256k1_generator_h);
        TEST_ASSERT(!res);
        // Test with wrong commitment
        memcpy(wrong_commit, p_vect->commit, sizeof(wrong_commit));
        wrong_commit[1 + (i & 31)] ^= 1;
        res = liquid_rangeproof_verify_value(p_vect->proof,
                                             p_vect->proof_len,
                                             p_vect->value,
                                             wrong_commit,
                                             sizeof(p_vect->commit),
                                             secp256k1_generator_h);
        TEST_ASSERT(!res);
    }
}

static void test_secp256k1_fe_is_quad_var(test_ctx_t *test_ctx) {
    unsigned char in[32] = { 0 };
    int iter;
    int is_quad;
    uint64_t res;

    // test with small numbers 0...63
    res = 0;
    for(iter = 0; iter < 64; ++iter) {
        in[31] = iter;
        is_quad = secp256k1_fe_is_quad_var(in) ? 1 : 0;
        res = (res << 1) | is_quad;
    }
    TEST_ASSERT(res == 0xe8d1f647bb39603eLLU);

    // pseudo-random values starting with 0xffff...ff
    res = 0;
    memset(in, 0xff, sizeof(in));
    for(iter = 0; iter < 64; ++iter) {
        is_quad = secp256k1_fe_is_quad_var(in) ? 1 : 0;
        res = (res << 1) | is_quad;
        cx_hash_sha256(in, 32, in, 32);
    }
    TEST_ASSERT(res == 0x94aff530bc06c53fLLU);
}

static void test_secp256k1_scalar_check_overflow(test_ctx_t *test_ctx) {
    uint8_t in[32];
    int iter;
    uint32_t res = 0;
    int ovf_flag;

    memcpy(in, secp256k1_scalar_max, sizeof(in));
    for(iter = 0x31; iter < 0x31 + 32; ++iter) {
        in[31] = iter;
        ovf_flag = secp256k1_scalar_check_overflow(in) ? 1 : 0;
        res = (res << 1) | ovf_flag;
    }
    TEST_ASSERT(res == 0x0000ffffLU);
}

void test_suite_liquid_proofs(test_ctx_t *test_ctx) {
    RUN_TEST(test_rangeproof_single_value);
    RUN_TEST(test_secp256k1_fe_is_quad_var);
    RUN_TEST(test_secp256k1_scalar_check_overflow);
}

#endif // IMPLEMENT_ON_DEVICE_TESTS