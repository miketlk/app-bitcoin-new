#pragma once

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_EXTENDED_PUBKEY = 0x00,
    REGISTER_WALLET = 0x02,
    GET_WALLET_ADDRESS = 0x03,
    SIGN_PSBT = 0x04,
    GET_MASTER_FINGERPRINT = 0x05,
    SIGN_MESSAGE = 0x10,
#ifdef HAVE_LIQUID
    LIQUID_GET_MASTER_BLINDING_KEY = 0xE1,
    LIQUID_GET_BLINDING_KEY = 0xE3,
#endif  // HAVE_LIQUID
} command_e;
