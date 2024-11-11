/**
 * This file containing unit tests is intended to be included at the end of the
 * corresponding source file.
 *
 * Not to be included in normal way as a header!
 */

static void test_elip150_derive_public_key(test_ctx_t *test_ctx) {
    static const uint8_t bare_pubkey[33] = {0x02, 0x86, 0xfc, 0x9a, 0x38, 0xe7, 0x65, 0xd9, 0x55,
                                            0xe9, 0xb0, 0xbc, 0xc1, 0x8f, 0xa9, 0xae, 0x81, 0xb0,
                                            0xc8, 0x93, 0xe2, 0xdd, 0x1e, 0xf5, 0x54, 0x2a, 0x9c,
                                            0x73, 0x78, 0x0a, 0x08, 0x6b, 0x90};
    static const uint8_t script[] = {0x00, 0x14, 0xb7, 0xc6, 0x4c, 0x32, 0xd9, 0xc3,
                                     0x7b, 0x30, 0xe0, 0x24, 0xe7, 0xd0, 0x28, 0xe0,
                                     0xfc, 0x6b, 0x0c, 0x4c, 0x5a, 0x92};
    static const uint8_t ref_pubkey[33] = {0x02, 0xb5, 0x4e, 0x55, 0x11, 0xb4, 0x77, 0x10, 0x04,
                                           0x86, 0x93, 0x82, 0xd1, 0xae, 0x7b, 0x51, 0x62, 0xee,
                                           0x19, 0x0c, 0x81, 0x4c, 0x2d, 0x8b, 0x10, 0x56, 0x2c,
                                           0xfd, 0xb2, 0x83, 0x32, 0xa2, 0xea};
    uint8_t out_pubkey[33];

    TEST_ASSERT(elip150_derive_public_key(bare_pubkey, script, sizeof(script), out_pubkey));
    TEST_ASSERT_EQUAL_MEMORY(out_pubkey, ref_pubkey, sizeof(ref_pubkey));
}

typedef struct {
    uint32_t length;
    const uint8_t *data;
} script_record_t;

static bool get_script_callback(void *state,
                                size_t descriptor_idx,
                                uint32_t bip44_address_index,
                                buffer_t *out_buffer) {
    if (LIQUID_ELIP151_RESERVED_INDEX != bip44_address_index) {
        return false;
    }

    const script_record_t *p_script = (const script_record_t *) PIC(state);
    for (size_t i = 0; p_script->data != NULL; i++, p_script++) {
        if (i == descriptor_idx) {
            return buffer_write_bytes(out_buffer,
                                      (const uint8_t *) PIC(p_script->data),
                                      p_script->length);
        }
    }
    return false;
}

static void test_elip151_derive_private_key_standard_chains(test_ctx_t *test_ctx) {
    static const uint8_t script0[] = {0x00, 0x14, 0xc7, 0x55, 0x88, 0x40, 0x33, 0x79,
                                      0xa9, 0xcc, 0xd0, 0xed, 0x60, 0x82, 0x2b, 0x79,
                                      0x30, 0xfb, 0xd6, 0x5c, 0xb3, 0xf2};
    static const uint8_t script1[] = {0x00, 0x14, 0xd5, 0xdf, 0x95, 0x24, 0x29, 0x2d,
                                      0xf6, 0xa5, 0xb6, 0x15, 0x13, 0x40, 0x41, 0x95,
                                      0x75, 0x16, 0xa2, 0xa4, 0x9e, 0xd5};
    static const script_record_t scripts[] = {
        {.length = sizeof(script0), .data = script0},
        {.length = sizeof(script1), .data = script1},
        {.data = NULL}  // Terminating record
    };
    static const uint8_t ref_privkey[32] = {0xb3, 0xba, 0xf9, 0x4d, 0x60, 0xcf, 0x84, 0x23,
                                            0xcd, 0x25, 0x72, 0x83, 0x57, 0x59, 0x97, 0xa2,
                                            0xc0, 0x06, 0x64, 0xce, 0xd3, 0xe8, 0xde, 0x00,
                                            0xf8, 0x72, 0x67, 0x03, 0x14, 0x2b, 0x19, 0x89};

    uint8_t out_privkey[32];
    TEST_ASSERT(elip151_derive_private_key(2, get_script_callback, (void *) scripts, out_privkey));
    TEST_ASSERT_EQUAL_MEMORY(out_privkey, ref_privkey, sizeof(ref_privkey));
}

static void test_elip151_derive_private_key_external_chain(test_ctx_t *test_ctx) {
    static const uint8_t script0[] = {0x00, 0x14, 0xc7, 0x55, 0x88, 0x40, 0x33, 0x79,
                                      0xa9, 0xcc, 0xd0, 0xed, 0x60, 0x82, 0x2b, 0x79,
                                      0x30, 0xfb, 0xd6, 0x5c, 0xb3, 0xf2};
    static const script_record_t scripts[] = {
        {.length = sizeof(script0), .data = script0},
        {.data = NULL}  // Terminating record
    };
    static const uint8_t ref_privkey[32] = {0xde, 0x9c, 0x5f, 0xb6, 0x24, 0x15, 0x46, 0x24,
                                            0x14, 0x6a, 0x8a, 0xea, 0x04, 0x89, 0xb3, 0x0f,
                                            0x05, 0xc7, 0x20, 0xee, 0xd6, 0xb4, 0x93, 0xb1,
                                            0xf3, 0xab, 0x63, 0x40, 0x5a, 0x11, 0xbf, 0x37};

    uint8_t out_privkey[32];
    TEST_ASSERT(elip151_derive_private_key(1, get_script_callback, (void *) scripts, out_privkey));
    TEST_ASSERT_EQUAL_MEMORY(out_privkey, ref_privkey, sizeof(ref_privkey));
}

static void test_elip151_derive_private_key_multisig_standard_chains(test_ctx_t *test_ctx) {
    static const uint8_t script0[] = {0x00, 0x20, 0x76, 0xc1, 0xc6, 0xad, 0x62, 0xc1, 0x21,
                                      0xb7, 0xcc, 0x8a, 0x72, 0xcd, 0x8c, 0xcf, 0x5b, 0xcb,
                                      0xe5, 0x36, 0x8b, 0x76, 0x7f, 0xc8, 0x0e, 0xeb, 0xcb,
                                      0x0a, 0xb5, 0xb5, 0x98, 0x11, 0xae, 0x21};
    static const uint8_t script1[] = {0x00, 0x20, 0xe8, 0x25, 0x01, 0xd1, 0x4c, 0xb5, 0x43,
                                      0x93, 0x8d, 0x20, 0xf0, 0xaa, 0x60, 0x0d, 0x3f, 0xfe,
                                      0x1e, 0x11, 0xc2, 0x28, 0xc5, 0x84, 0x27, 0x6b, 0x85,
                                      0xd6, 0x4f, 0x7d, 0x59, 0x79, 0xb5, 0x6e};
    static const script_record_t scripts[] = {
        {.length = sizeof(script0), .data = script0},
        {.length = sizeof(script1), .data = script1},
        {.data = NULL}  // Terminating record
    };
    static const uint8_t ref_privkey[32] = {0x7f, 0xcc, 0x1b, 0x9a, 0x20, 0xbb, 0xf6, 0x11,
                                            0xd1, 0x57, 0x01, 0x61, 0x92, 0xa7, 0xd2, 0x8e,
                                            0x35, 0x30, 0x33, 0xcf, 0xa6, 0xa4, 0x88, 0x5b,
                                            0x3c, 0x48, 0xfa, 0x5f, 0xf9, 0xce, 0x18, 0x81};

    uint8_t out_privkey[32];
    TEST_ASSERT(elip151_derive_private_key(2, get_script_callback, (void *) scripts, out_privkey));
    TEST_ASSERT_EQUAL_MEMORY(out_privkey, ref_privkey, sizeof(ref_privkey));
}

void test_suite_liquid(test_ctx_t *test_ctx) {
    RUN_TEST(test_elip150_derive_public_key);
    RUN_TEST(test_elip151_derive_private_key_standard_chains);
    RUN_TEST(test_elip151_derive_private_key_external_chain);
    RUN_TEST(test_elip151_derive_private_key_multisig_standard_chains);
}
