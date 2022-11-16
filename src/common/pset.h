#pragma once

// clang-format off

// Maximum length of identifier prefix of a proprietary key
#define PSBT_PROPRIETARY_ID_MAX_LENGTH 8

#define PSBT_KEY_ELEMENTS_LEGACY(x) \
	(const uint8_t[]){0xfc, 0x08, 'e', 'l', 'e', 'm', 'e', 'n', 't', 's', (x)}
#define PSBT_KEY_ELEMENTS(x) (uint8_t[]){0xfc, 0x04, 'p', 's', 'e', 't', (x)}

#define PSBT_ELEMENTS_GLOBAL_SCALAR PSBT_KEY_ELEMENTS(0x00)
#define PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE PSBT_KEY_ELEMENTS(0x01)

#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE PSBT_KEY_ELEMENTS(0x00)
#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT PSBT_KEY_ELEMENTS(0x01)
#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF PSBT_KEY_ELEMENTS(0x02)
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF PSBT_KEY_ELEMENTS(0x03)
#define PSBT_ELEMENTS_IN_PEG_IN_TX PSBT_KEY_ELEMENTS(0x04)
#define PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF PSBT_KEY_ELEMENTS(0x05)
#define PSBT_ELEMENTS_IN_PEG_IN_GENESIS_HASH PSBT_KEY_ELEMENTS(0x06)
#define PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT PSBT_KEY_ELEMENTS(0x07)
#define PSBT_ELEMENTS_IN_PEG_IN_VALUE PSBT_KEY_ELEMENTS(0x08)
#define PSBT_ELEMENTS_IN_PEG_IN_WITNESS PSBT_KEY_ELEMENTS(0x09)
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT PSBT_KEY_ELEMENTS(0x0a)
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT PSBT_KEY_ELEMENTS(0x0b)
#define PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE PSBT_KEY_ELEMENTS(0x0c)
#define PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY PSBT_KEY_ELEMENTS(0x0d)
#define PSBT_ELEMENTS_IN_UTXO_RANGEPROOF PSBT_KEY_ELEMENTS(0x0e)
#define PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF PSBT_KEY_ELEMENTS(0x0f)
#define PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF PSBT_KEY_ELEMENTS(0x10)
#define PSBT_ELEMENTS_IN_EXPLICIT_VALUE PSBT_KEY_ELEMENTS(0x11)
#define PSBT_ELEMENTS_IN_VALUE_PROOF PSBT_KEY_ELEMENTS(0x12)
#define PSBT_ELEMENTS_IN_EXPLICIT_ASSET PSBT_KEY_ELEMENTS(0x13)
#define PSBT_ELEMENTS_IN_ASSET_PROOF PSBT_KEY_ELEMENTS(0x14)
#define PSBT_ELEMENTS_IN_BLINDED_ISSUANCE PSBT_KEY_ELEMENTS(0x15)

#define	PSBT_ELEMENTS_OUT_VALUE_COMMITMENT PSBT_KEY_ELEMENTS(0x01)
#define	PSBT_ELEMENTS_OUT_ASSET PSBT_KEY_ELEMENTS(0x02)
#define	PSBT_ELEMENTS_OUT_ASSET_COMMITMENT PSBT_KEY_ELEMENTS(0x03)
#define	PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF PSBT_KEY_ELEMENTS(0x04)
#define	PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF PSBT_KEY_ELEMENTS(0x05)
#define	PSBT_ELEMENTS_OUT_BLINDING_PUBKEY PSBT_KEY_ELEMENTS(0x06)
#define	PSBT_ELEMENTS_OUT_ECDH_PUBKEY PSBT_KEY_ELEMENTS(0x07)
#define	PSBT_ELEMENTS_OUT_BLINDER_INDEX PSBT_KEY_ELEMENTS(0x08)
#define	PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF PSBT_KEY_ELEMENTS(0x09)
#define	PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF PSBT_KEY_ELEMENTS(0x0a)
