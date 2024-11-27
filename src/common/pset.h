#pragma once

// clang-format off

/// Maximum length of identifier prefix of a proprietary key
#define PSBT_PROPRIETARY_ID_MAX_LENGTH 8

/// Evaluates to 0 if condition is true, otherwise compilation fails
#define PSET_H_PREPROC_CHECK(condition)  (sizeof(char[1 - 2 * ((condition) ? 0 : 1)]) ? 0 : 1)

/// Defines Elements proprietary key for single-byte subkeytype
#define PSBT_KEY_ELEMENTS(x) \
		(const uint8_t[]){ PSET_H_PREPROC_CHECK((x) <= 0xfc) | 0xfc, 0x04, 'p', 's', 'e', 't', (x) }

/// Defines proprietary key for Hardware Wallet Extensions (ELIP 100)
#define PSBT_KEY_ELEMENTS_HWW(x) \
		(const uint8_t[]){ PSET_H_PREPROC_CHECK((x) <= 0xfc) | 0xfc, 0x08, \
		                   'p', 's', 'e', 't', '_', 'h', 'w', 'w', (x) }

/// Scalar Offset
#define PSBT_ELEMENTS_GLOBAL_SCALAR PSBT_KEY_ELEMENTS(0x00)
/// Elements Transaction Modifiable Flag
#define PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE PSBT_KEY_ELEMENTS(0x01)
/// ELIP 100: Asset Metadata
#define PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA PSBT_KEY_ELEMENTS_HWW(0x00)
/// ELIP 100: Reissuance Token Definition
#define PSBT_ELEMENTS_HWW_GLOBAL_REISSUANCE_TOKEN PSBT_KEY_ELEMENTS_HWW(0x01)

/// Issuance Value
#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE PSBT_KEY_ELEMENTS(0x00)
/// Issuance Value Commitment
#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT PSBT_KEY_ELEMENTS(0x01)
/// Issuance Value Rangeproof
#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF PSBT_KEY_ELEMENTS(0x02)
/// Issuance Inflation Keys Rangeproof
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_RANGEPROOF PSBT_KEY_ELEMENTS(0x03)
/// Peg-in Transaction
#define PSBT_ELEMENTS_IN_PEG_IN_TX PSBT_KEY_ELEMENTS(0x04)
/// Peg-in Transaction Output Proof
#define PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF PSBT_KEY_ELEMENTS(0x05)
/// Peg-in Genesis Hash
#define PSBT_ELEMENTS_IN_PEG_IN_GENESIS_HASH PSBT_KEY_ELEMENTS(0x06)
/// Peg-in Claim Script
#define PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT PSBT_KEY_ELEMENTS(0x07)
/// Peg-in Value
#define PSBT_ELEMENTS_IN_PEG_IN_VALUE PSBT_KEY_ELEMENTS(0x08)
/// Peg-in Witness
#define PSBT_ELEMENTS_IN_PEG_IN_WITNESS PSBT_KEY_ELEMENTS(0x09)
/// Issuance Inflation Keys Amount
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT PSBT_KEY_ELEMENTS(0x0a)
/// Issuance Inflation Keys Amount Commitment
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT PSBT_KEY_ELEMENTS(0x0b)
/// Issuance Blinding Nonce
#define PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE PSBT_KEY_ELEMENTS(0x0c)
/// Issuance Asset Entropy
#define PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY PSBT_KEY_ELEMENTS(0x0d)
/// UTXO Rangeproof
#define PSBT_ELEMENTS_IN_UTXO_RANGEPROOF PSBT_KEY_ELEMENTS(0x0e)
/// Issuance Blind Value Proof
#define PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF PSBT_KEY_ELEMENTS(0x0f)
/// Issuance Inflation Keys Blind Value Proof
#define PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF PSBT_KEY_ELEMENTS(0x10)
/// Explicit Value
#define PSBT_ELEMENTS_IN_EXPLICIT_VALUE PSBT_KEY_ELEMENTS(0x11)
/// Explicit Value Proof
#define PSBT_ELEMENTS_IN_VALUE_PROOF PSBT_KEY_ELEMENTS(0x12)
/// Explicit Asset
#define PSBT_ELEMENTS_IN_EXPLICIT_ASSET PSBT_KEY_ELEMENTS(0x13)
/// Explicit Asset Proof
#define PSBT_ELEMENTS_IN_ASSET_PROOF PSBT_KEY_ELEMENTS(0x14)
/// Blinded Issuance Flag
#define PSBT_ELEMENTS_IN_BLINDED_ISSUANCE PSBT_KEY_ELEMENTS(0x15)

/// Value Commitment
#define	PSBT_ELEMENTS_OUT_VALUE_COMMITMENT PSBT_KEY_ELEMENTS(0x01)
/// Asset Tag
#define	PSBT_ELEMENTS_OUT_ASSET PSBT_KEY_ELEMENTS(0x02)
/// Asset Commitment
#define	PSBT_ELEMENTS_OUT_ASSET_COMMITMENT PSBT_KEY_ELEMENTS(0x03)
/// Value Rangeproof
#define	PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF PSBT_KEY_ELEMENTS(0x04)
/// Asset Surjection Proof
#define	PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF PSBT_KEY_ELEMENTS(0x05)
/// Blinding Pubkey
#define	PSBT_ELEMENTS_OUT_BLINDING_PUBKEY PSBT_KEY_ELEMENTS(0x06)
/// Ephemeral ECDH Pubkey
#define	PSBT_ELEMENTS_OUT_ECDH_PUBKEY PSBT_KEY_ELEMENTS(0x07)
/// Blinder Index
#define	PSBT_ELEMENTS_OUT_BLINDER_INDEX PSBT_KEY_ELEMENTS(0x08)
/// Blind Value Proof
#define	PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF PSBT_KEY_ELEMENTS(0x09)
/// Blind Asset Proof
#define	PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF PSBT_KEY_ELEMENTS(0x0a)
