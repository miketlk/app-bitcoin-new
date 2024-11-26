/**
 * This file containing unit tests is intended to be included at the end of the
 * corresponding source file.
 *
 * Not to be included in normal way as a header!
 */

typedef struct {
    uint64_t value;
    uint8_t commit[33];
    uint8_t proof[73];
    uint16_t proof_len;
} value_proof_test_data_t;

typedef struct {
    uint8_t proof[70];
    size_t plen;
    uint8_t input_tag[65];
    uint8_t output_tag[65];
} asset_proof_test_data_t;

typedef struct {
    uint8_t fe[32];
    uint8_t ge[65];
} shallue_van_de_woestijne_test_data_t;

typedef struct {
    uint8_t seed[32];
    uint8_t gen[65];
} generator_generate_test_data_t;

#include "liquid_proofs_test_data.h"

static void test_liquid_rangeproof_verify_exact(test_ctx_t *test_ctx) {
    int n_vectors = sizeof(value_proof_test_data) / sizeof(value_proof_test_data[0]);
    const value_proof_test_data_t *p_vect = value_proof_test_data;
    uint8_t wrong_commit[33];
    bool res;

    for (int i = 0; i < n_vectors; ++i, p_vect++) {
        // Test with correct parameters
        res = liquid_rangeproof_verify_exact(p_vect->proof,
                                             p_vect->proof_len,
                                             p_vect->value,
                                             p_vect->commit,
                                             sizeof(p_vect->commit),
                                             secp256k1_generator_h);
        TEST_ASSERT(res);

        // Test with wrong value
        res = liquid_rangeproof_verify_exact(p_vect->proof,
                                             p_vect->proof_len,
                                             p_vect->value ^ (1 << (i & 63)), /* corrupt */
                                             p_vect->commit,
                                             sizeof(p_vect->commit),
                                             secp256k1_generator_h);
        TEST_ASSERT(!res);

        // Test with wrong commitment
        memcpy(wrong_commit, p_vect->commit, sizeof(wrong_commit));
        wrong_commit[1 + (i & 31)] ^= 1;
        res = liquid_rangeproof_verify_exact(p_vect->proof,
                                             p_vect->proof_len,
                                             p_vect->value,
                                             wrong_commit,
                                             sizeof(p_vect->commit),
                                             secp256k1_generator_h);
        TEST_ASSERT(!res);
    }
}

static void test_secp256k1_fe_is_quad_var(test_ctx_t *test_ctx) {
    secp256k1_fe in = {.n = {0}};
    int iter;
    bool is_quad;
    uint64_t res;

    // test with small numbers 0...63
    res = 0;
    for (iter = 0; iter < 64; ++iter) {
        in.n[31] = iter;
        TEST_ASSERT(secp256k1_fe_is_quad_var(&in, &is_quad));
        res = (res << 1) | is_quad;
    }
    TEST_ASSERT(res == 0xe8d1f647bb39603eLLU);

    // pseudo-random values starting with 0xffff...ff
    res = 0;
    memset(in.n, 0xff, sizeof(in.n));
    for (iter = 0; iter < 64; ++iter) {
        TEST_ASSERT(secp256k1_fe_is_quad_var(&in, &is_quad));
        res = (res << 1) | is_quad;
        cx_hash_sha256(in.n, 32, in.n, 32);
    }
    TEST_ASSERT(res == 0x94aff530bc06c53fLLU);
}

static void test_secp256k1_scalar_check_overflow(test_ctx_t *test_ctx) {
    secp256k1_scalar in;
    int iter;
    uint32_t res = 0;
    bool ovf_flag;

    memcpy(in.n, secp256k1_scalar_max, sizeof(in.n));
    for (iter = 0x31; iter < 0x31 + 32; ++iter) {
        in.n[31] = iter;
        TEST_ASSERT(secp256k1_scalar_check_overflow(&in, &ovf_flag));
        res = (res << 1) | (int) ovf_flag;
    }
    TEST_ASSERT(res == 0x0000ffffLU);
}

static void test_liquid_surjectionproof_verify_single(test_ctx_t *test_ctx) {
    int n_vectors = sizeof(asset_proof_test_data) / sizeof(asset_proof_test_data[0]);
    const asset_proof_test_data_t *p_vect = asset_proof_test_data;
    uint8_t param[100];
    size_t param_size;

    for (int i = 0; i < n_vectors; ++i, p_vect++) {
        // Test with correct parameters
        TEST_ASSERT(liquid_surjectionproof_verify_single(p_vect->proof,
                                                         p_vect->plen,
                                                         p_vect->input_tag,
                                                         p_vect->output_tag));

        // Test with wrong proof
        for (int j = 0; j < 10; ++j) {
            param_size = MIN(p_vect->plen, sizeof(param));
            memcpy(param, p_vect->proof, param_size);
            param[(i * 10 + j) % param_size] ^= 1;
            TEST_ASSERT_FALSE(liquid_surjectionproof_verify_single(param,
                                                                   p_vect->plen,
                                                                   p_vect->input_tag,
                                                                   p_vect->output_tag));
        }

        // Test with wrong input tag
        for (int j = 0; j < 10; ++j) {
            param_size = MIN(sizeof(p_vect->input_tag), sizeof(param));
            memcpy(param, p_vect->input_tag, param_size);
            param[(1 + i * 10 + j) % param_size] ^= 1;
            TEST_ASSERT_FALSE(liquid_surjectionproof_verify_single(p_vect->proof,
                                                                   p_vect->plen,
                                                                   param,
                                                                   p_vect->output_tag));
        }

        // Test with wrong output tag
        for (int j = 0; j < 10; ++j) {
            param_size = MIN(sizeof(p_vect->output_tag), sizeof(param));
            memcpy(param, p_vect->output_tag, param_size);
            param[(1 + i * 10 + j) % param_size] ^= 1;
            TEST_ASSERT_FALSE(liquid_surjectionproof_verify_single(p_vect->proof,
                                                                   p_vect->plen,
                                                                   p_vect->input_tag,
                                                                   param));
        }
    }
}

static void test_liquid_generator_parse(test_ctx_t *test_ctx) {
    uint8_t serialized[LIQUID_COMMITMENT_LEN] = {
        0x0b, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45,
        0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c,
        0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5};
    static const uint8_t ref_parsed[LIQUID_GENERATOR_LEN] = {
        0x04, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e,
        0x95, 0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab,
        0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5, 0xe5, 0x1e, 0x97, 0x01, 0x59, 0xc2,
        0x3c, 0xc6, 0x5c, 0x3a, 0x7b, 0xe6, 0xb9, 0x93, 0x15, 0x11, 0x08, 0x09, 0xcd,
        0x9a, 0xcd, 0x99, 0x2f, 0x1e, 0xdc, 0x9b, 0xce, 0x55, 0xaf, 0x30, 0x17, 0x05};
    uint8_t parsed[LIQUID_GENERATOR_LEN];

    TEST_ASSERT(liquid_generator_parse(parsed, serialized));
    TEST_ASSERT_EQUAL_MEMORY(parsed, ref_parsed, LIQUID_GENERATOR_LEN);
    serialized[0] = 0x0a;
    TEST_ASSERT(liquid_generator_parse(parsed, serialized));
    serialized[0] = 0x08;
    TEST_ASSERT_FALSE(liquid_generator_parse(parsed, serialized));
}

static void test_shallue_van_de_woestijne(test_ctx_t *test_ctx) {
    int n_vectors =
        sizeof(shallue_van_de_woestijne_test_data) / sizeof(shallue_van_de_woestijne_test_data[0]);
    const shallue_van_de_woestijne_test_data_t *p_vect = shallue_van_de_woestijne_test_data;
    secp256k1_ge ge;

    for (int i = 0; i < n_vectors; ++i, p_vect++) {
        TEST_ASSERT(shallue_van_de_woestijne(&ge, (const secp256k1_fe *) p_vect->fe));
        TEST_ASSERT_EQUAL_MEMORY(&ge, p_vect->ge, sizeof(p_vect->ge));
    }
}

static void test_liquid_generator_generate(test_ctx_t *test_ctx) {
    int n_vectors = sizeof(generator_generate_test_data) / sizeof(generator_generate_test_data[0]);
    const generator_generate_test_data_t *p_vect = generator_generate_test_data;
    uint8_t gen[LIQUID_GENERATOR_LEN] = {0};
    uint8_t seed_reversed[32];

    for (int i = 0; i < n_vectors; ++i, p_vect++) {
        // Reverse seed to comply with new API
        reverse_copy(seed_reversed, p_vect->seed, sizeof(seed_reversed));
        TEST_ASSERT(liquid_generator_generate(gen, seed_reversed));
        TEST_ASSERT_EQUAL_MEMORY(gen, p_vect->gen, sizeof(p_vect->gen));
    }
}

void test_suite_liquid_proofs(test_ctx_t *test_ctx) {
    RUN_TEST(test_liquid_rangeproof_verify_exact);
    RUN_TEST(test_secp256k1_fe_is_quad_var);
    RUN_TEST(test_secp256k1_scalar_check_overflow);
    RUN_TEST(test_liquid_surjectionproof_verify_single);
    RUN_TEST(test_liquid_generator_parse);
    RUN_TEST(test_shallue_van_de_woestijne);
    RUN_TEST(test_liquid_generator_generate);
}
