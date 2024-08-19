#pragma once

/**
 * Instruction class of the Bitcoin application.
 */
#define CLA_APP 0xE1

/**
 * Encodes the protocol version, which is passed in the p2 field of APDUs.
 */
#define CURRENT_PROTOCOL_VERSION 1

/**
 * Maximum length of SegWit prefix in characters
 */
#ifdef HAVE_LIQUID
#define MAX_SEGWIT_PREFIX_LENGTH 3
#else
#define MAX_SEGWIT_PREFIX_LENGTH sizeof(COIN_NATIVE_SEGWIT_PREFIX)
#endif

#ifdef HAVE_LIQUID
#define MAX_ADDRESS_LENGTH_STR (118 + MAX_SEGWIT_PREFIX_LENGTH)
#else // HAVE_LIQUID
/**
 * Maximum length of a serialized address (in characters).
 * Segwit addresses can reach 74 characters; 76 on regtest because of the longer "bcrt" prefix.
 */
#define MAX_ADDRESS_LENGTH_STR (72 + sizeof(COIN_NATIVE_SEGWIT_PREFIX))
#endif // HAVE_LIQUID

/**
 * Maximum transaction length (bytes).
 */
#define MAX_TRANSACTION_LEN 510

/**
 * Maximum DER-encoded signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72

/**
 * Maximum scriptPubKey length for an input that we can sign.
 */
#define MAX_PREVOUT_SCRIPTPUBKEY_LEN 34  // P2WSH's scriptPubKeys are the longest supported

/**
 * Maximum scriptPubKey length for an output that we can recognize.
 */
#define MAX_OUTPUT_SCRIPTPUBKEY_LEN 83  // max 83 for OP_RETURN; other scripts are shorter

/**
 * Maximum length of a wallet registered into the device (characters), excluding terminating NULL.
 */
#define MAX_WALLET_NAME_LENGTH 64

/**
 * Maximum length (characters) of a base58check-encoded serialized extended pubkey.
 */
#define MAX_SERIALIZED_PUBKEY_LENGTH 113

/**
 * Maximum number of inputs supported while signing a transaction.
 */
#define MAX_N_INPUTS_CAN_SIGN 512

// SIGHASH flags
#define SIGHASH_DEFAULT      0x00000000
#define SIGHASH_ALL          0x00000001
#define SIGHASH_NONE         0x00000002
#define SIGHASH_SINGLE       0x00000003
#define SIGHASH_ANYONECANPAY 0x00000080
#ifdef HAVE_LIQUID
#define SIGHASH_RANGEPROOF   0x00000040
#endif

/**
 * Number of decimal digits in fractional part of Bitcoin amount
 * (Satoshis per Bitcoin expressed as a power of 10)
 */
#define BITCOIN_DECIMALS 8

/**
 * Maximum length (characters) of an asset ticker
 */
#ifdef HAVE_LIQUID
#define MAX_ASSET_TICKER_LENGTH 10
#else
#define MAX_ASSET_TICKER_LENGTH 5
#endif

/**
 * Number of bytes in SHA-256 hash code
 */
#define SHA256_LEN 32

/**
 * Maximum length (characters) of transaction type.
 * Currently supported types: 'transaction', 'issuance', 'reissuance', 'burn'
 */
#define MAX_TRANSACTION_TYPE_LEN 15

#define SEQUENCE_LOCKTIME_TYPE_FLAG (1 << 22)
#define LOCKTIME_THRESHOLD          500000000

#define MAX_STANDARD_P2WSH_STACK_ITEMS 100U
#define MAX_STANDARD_P2WSH_SCRIPT_SIZE 3600U
#define MAX_OPS_PER_SCRIPT             201U

/**
 * Maximum length of script in bytes
 */
#define MAX_SCRIPT_LEN 34

/**
 * Main app icon
 */
#ifdef HAVE_LIQUID
    #define APP_MAIN_ICON C_liquid_logo
#else
    #define APP_MAIN_ICON C_bitcoin_logo
#endif

/**
 * Main app icon in high resolution
 */
#ifdef HAVE_LIQUID
    #define APP_MAIN_ICON_64 C_Liquid_64px
#else
    #define APP_MAIN_ICON_64 C_Bitcoin_64px
#endif
