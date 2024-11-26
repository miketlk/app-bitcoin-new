#ifdef HAVE_LIQUID

#include <stdint.h>
#include <string.h>
#include "crypto.h"
#include "util.h"
#include "../boilerplate/dispatcher.h"
#include "../common/merkle.h"
#include "../common/psbt.h"
#include "../common/pset.h"
#include "../handler/lib/get_merkleized_map.h"
#include "../handler/lib/get_merkleized_map_value.h"
#include "../handler/lib/pset_parse_rawtx.h"
#include "../handler/sign_psbt/update_hashes_with_map_value.h"
#include "liquid_pset.h"

bool pset_test_key(buffer_t *buffer, const uint8_t *ref_key) {
    // Offsets within proprietary key byte array, assuming length and types are single-byte.
    enum { OFF_KEYTYPE = 0, OFF_ID_LEN, OFF_ID };

    // Sanity check
    if (!buffer || !ref_key || ref_key[OFF_KEYTYPE] != 0xfc ||
        ref_key[OFF_ID_LEN] > PSBT_PROPRIETARY_ID_MAX_LENGTH) {
        return false;
    }

    buffer_snapshot_t snapshot = buffer_snapshot(buffer);
    int subkeytype_len = varint_size_by_prefix(ref_key[OFF_ID + ref_key[OFF_ID_LEN]]);
    uint8_t id_len;
    bool result = true;

    // Only single-byte ID length is supported
    if (buffer_read_u8(buffer, &id_len) && id_len == ref_key[OFF_ID_LEN]) {
        uint8_t curr_byte;
        const uint8_t *p_ref_key = ref_key + OFF_ID;
        // Compare all bytes of identifier + all bytes of sub-keytype
        for (int i = 0; i < id_len + subkeytype_len; ++i, p_ref_key++) {
            if (!buffer_read_u8(buffer, &curr_byte) || curr_byte != *p_ref_key) {
                result = false;
                break;
            }
        }
    } else {
        result = false;
    }

    buffer_restore(buffer, snapshot);
    return result;
}

bool pset_get_asset_tag(dispatcher_context_t *dc,
                        const merkleized_map_commitment_t *map,
                        const uint8_t *key,
                        int key_len,
                        tx_asset_t *asset) {
    if (!dc || !map || !key || !key_len || !asset) {
        return false;
    }

    asset->is_blinded = false;

    if (sizeof(asset->tag) ==
        call_get_merkleized_map_value(dc, map, key, key_len, asset->tag, sizeof(asset->tag))) {
        reverse_inplace(asset->tag, sizeof(asset->tag));
        return true;
    }
    return false;
}

static void hashing_output_keys_callback(dispatcher_context_t *dc,
                                         uint32_t *p_key_presence,
                                         const merkleized_map_commitment_t *map_commitment,
                                         int i,
                                         buffer_t *data) {
    UNUSED(dc);
    UNUSED(map_commitment);
    UNUSED(i);
    UNUSED(data);

    pset_detect_output_key(data, p_key_presence);
}

int pset_hash_output(dispatcher_context_t *dc,
                     uint8_t outputs_root[32],
                     unsigned int n_outputs,
                     int output_index,
                     cx_hash_t *hash_context,
                     cx_hash_t *rangeproof_hash_context) {
    merkleized_map_commitment_t ith_map;
    uint32_t key_presence = 0;

    // get this output's merkelized map
    int res = call_get_merkleized_map_with_callback(
        dc,
        (void *) &key_presence,
        outputs_root,
        n_outputs,
        output_index,
        (merkle_tree_elements_callback_t) hashing_output_keys_callback,
        &ith_map);

    if (res < 0) {
        return -1;
    }

    if (hash_context) {
        // hash asset or asset commitment
        if (key_presence & HAS_ASSET_COMMITMENT) {
            uint8_t commitment[33];
            if (sizeof(commitment) !=
                call_get_merkleized_map_value(dc,
                                              &ith_map,
                                              PSBT_ELEMENTS_OUT_ASSET_COMMITMENT,
                                              sizeof(PSBT_ELEMENTS_OUT_ASSET_COMMITMENT),
                                              commitment,
                                              sizeof(commitment))) {
                return -1;
            }
            crypto_hash_update(hash_context, commitment, sizeof(commitment));
        } else if (key_presence & HAS_ASSET) {
            uint8_t asset[32];
            if (sizeof(asset) != call_get_merkleized_map_value(dc,
                                                               &ith_map,
                                                               PSBT_ELEMENTS_OUT_ASSET,
                                                               sizeof(PSBT_ELEMENTS_OUT_ASSET),
                                                               asset,
                                                               sizeof(asset))) {
                return -1;
            }
            crypto_hash_update_u8(hash_context, 0x01);
            crypto_hash_update(hash_context, asset, sizeof(asset));
        } else {
            PRINTF("No asset nor asset commitment provided for output %i", output_index);
            return -1;
        }

        // hash amount or value commitment
        if (key_presence & HAS_VALUE_COMMITMENT) {
            uint8_t commitment[33];
            if (sizeof(commitment) !=
                call_get_merkleized_map_value(dc,
                                              &ith_map,
                                              PSBT_ELEMENTS_OUT_VALUE_COMMITMENT,
                                              sizeof(PSBT_ELEMENTS_OUT_VALUE_COMMITMENT),
                                              commitment,
                                              sizeof(commitment))) {
                return -1;
            }
            crypto_hash_update(hash_context, commitment, sizeof(commitment));
        } else if (key_presence & HAS_VALUE) {
            uint8_t value_raw[8];
            if (sizeof(value_raw) != call_get_merkleized_map_value(dc,
                                                                   &ith_map,
                                                                   (uint8_t[]){PSBT_OUT_AMOUNT},
                                                                   1,
                                                                   value_raw,
                                                                   sizeof(value_raw))) {
                return -1;
            }
            crypto_hash_update_u8(hash_context, 0x01);
            for (int i = 7; i >= 0; --i) {
                // Value is serialized as big endian
                crypto_hash_update_u8(hash_context, value_raw[i]);
            }
        } else {
            PRINTF("No value commitment nor amount provided for output %i", output_index);
            return -1;
        }

        // hash ephemeral ECDH pubkey
        if (key_presence & HAS_ECDH_PUBKEY) {
            uint8_t ecdh_pubkey[33];
            if (sizeof(ecdh_pubkey) !=
                call_get_merkleized_map_value(dc,
                                              &ith_map,
                                              PSBT_ELEMENTS_OUT_ECDH_PUBKEY,
                                              sizeof(PSBT_ELEMENTS_OUT_ECDH_PUBKEY),
                                              ecdh_pubkey,
                                              sizeof(ecdh_pubkey))) {
                return -1;
            }
            crypto_hash_update(hash_context, ecdh_pubkey, sizeof(ecdh_pubkey));
        } else {
            crypto_hash_update_u8(hash_context, 0x00);
        }

        // hash scriptPubKey
        {
            uint8_t out_script[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
            int out_script_len = call_get_merkleized_map_value(dc,
                                                               &ith_map,
                                                               (uint8_t[]){PSBT_OUT_SCRIPT},
                                                               1,
                                                               out_script,
                                                               sizeof(out_script));
            if (out_script_len == -1) {
                return -1;
            }
            crypto_hash_update_varint(hash_context, out_script_len);
            crypto_hash_update(hash_context, out_script, out_script_len);
        }
    }

    if (rangeproof_hash_context) {
        static const uint32_t witness_mask = HAS_VALUE_RANGEPROOF | HAS_ASSET_SURJECTION_PROOF;
        if ((key_presence & witness_mask) == witness_mask) {  // Output has witness
            // update hash with range proof
            res = update_hashes_with_map_value(dc,
                                               &ith_map,
                                               PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF,
                                               sizeof(PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF),
                                               NULL,
                                               rangeproof_hash_context);
            if (res < 0) {
                PRINTF("Error fetching range proof\n");
                return -1;
            }

            // update hash with surjection proof
            res = update_hashes_with_map_value(dc,
                                               &ith_map,
                                               PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF,
                                               sizeof(PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF),
                                               NULL,
                                               rangeproof_hash_context);
            if (res < 0) {
                PRINTF("Error fetching surjection proof\n");
                return -1;
            }
        } else if ((key_presence & witness_mask) == 0) {  // No output witness
            crypto_hash_update_zeros(rangeproof_hash_context, 2);
        } else {  // Incomplete witness
            PRINTF("Unsupported output witness configuration\n");
            return -1;
        }
    }

    return 0;
}

bool pset_hash_input_issuance(dispatcher_context_t *dc,
                              const merkleized_map_commitment_t *map,
                              uint32_t key_presence,
                              cx_hash_t *hash_context) {
    // Hash nonce
    if (key_presence & HAS_ISSUANCE_BLINDING_NONCE) {
        uint8_t nonce[32];
        if (sizeof(nonce) !=
            call_get_merkleized_map_value(dc,
                                          map,
                                          PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE,
                                          sizeof(PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE),
                                          nonce,
                                          sizeof(nonce))) {
            PRINTF("Error fetching issuance blinding nonce\n");
            return false;
        }
        crypto_hash_update(hash_context, nonce, sizeof(nonce));
    } else {
        // Zero for new asset issuance
        crypto_hash_update_zeros(hash_context, 32);
    }

    // Hash entropy
    if (key_presence & HAS_ISSUANCE_ASSET_ENTROPY) {
        uint8_t entropy[32];
        if (sizeof(entropy) !=
            call_get_merkleized_map_value(dc,
                                          map,
                                          PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY,
                                          sizeof(PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY),
                                          entropy,
                                          sizeof(entropy))) {
            PRINTF("Error fetching issuance asset entropy\n");
            return false;
        }
        crypto_hash_update(hash_context, entropy, sizeof(entropy));
    } else {
        PRINTF("No issuance asset entropy provided\n");
        return false;
    }

    // Hash amount commitment
    if (key_presence & HAS_ISSUANCE_VALUE_COMMITMENT) {
        uint8_t commitment[33];
        if (sizeof(commitment) !=
            call_get_merkleized_map_value(dc,
                                          map,
                                          PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT,
                                          sizeof(PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT),
                                          commitment,
                                          sizeof(commitment))) {
            PRINTF("Error fetching issuance value commitment\n");
            return false;
        }
        crypto_hash_update(hash_context, commitment, sizeof(commitment));
    } else if (key_presence & HAS_ISSUANCE_VALUE) {
        uint8_t value[8];
        if (sizeof(value) != call_get_merkleized_map_value(dc,
                                                           map,
                                                           PSBT_ELEMENTS_IN_ISSUANCE_VALUE,
                                                           sizeof(PSBT_ELEMENTS_IN_ISSUANCE_VALUE),
                                                           value,
                                                           sizeof(value))) {
            PRINTF("Error fetching issuance value\n");
            return false;
        }
        reverse_inplace(value, sizeof(value));
        crypto_hash_update_u8(hash_context, 0x01);
        crypto_hash_update(hash_context, value, sizeof(value));
    } else {
        crypto_hash_update_u8(hash_context, 0x00);
    }

    // Hash token commitment
    if (key_presence & HAS_ISSUANCE_INFLATION_KEYS_COMMITMENT) {
        uint8_t commitment[33];
        if (sizeof(commitment) != call_get_merkleized_map_value(
                                      dc,
                                      map,
                                      PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT,
                                      sizeof(PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT),
                                      commitment,
                                      sizeof(commitment))) {
            PRINTF("Error fetching issuance inflation keys commitment\n");
            return false;
        }
        crypto_hash_update(hash_context, commitment, sizeof(commitment));
    } else if (key_presence & HAS_ISSUANCE_INFLATION_KEYS_AMOUNT) {
        uint8_t value[8];
        if (sizeof(value) !=
            call_get_merkleized_map_value(dc,
                                          map,
                                          PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT,
                                          sizeof(PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT),
                                          value,
                                          sizeof(value))) {
            PRINTF("Error fetching issuance inflation keys amount\n");
            return false;
        }
        reverse_inplace(value, sizeof(value));
        crypto_hash_update_u8(hash_context, 0x01);
        crypto_hash_update(hash_context, value, sizeof(value));
    } else {
        crypto_hash_update_u8(hash_context, 0x00);
    }

    return true;
}

const char *pset_get_tx_type_by_flags(uint32_t flags) {
    switch (flags) {
        case TX_TYPE_ISSUANCE:
            return "issuance";

        case TX_TYPE_REISSUANCE:
            return "reissuance";

        case TX_TYPE_BURN:
            return "burn";

        default:
            return NULL;
    }
}

void pset_detect_input_key(buffer_t *data, uint32_t *p_key_presence) {
    if (!data || !p_key_presence) {
        return;
    }

    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        buffer_snapshot_t snapshot = buffer_snapshot(data);

        uint8_t keytype;
        buffer_read_u8(data, &keytype);
        if (keytype == PSBT_IN_WITNESS_UTXO) {
            *p_key_presence |= HAS_WITNESS_UTXO;
        } else if (keytype == PSBT_IN_NON_WITNESS_UTXO) {
            *p_key_presence |= HAS_NONWITNESS_UTXO;
        } else if (keytype == PSBT_IN_REDEEM_SCRIPT) {
            *p_key_presence |= HAS_REDEEM_SCRIPT;
        } else if (keytype == PSBT_IN_SIGHASH_TYPE) {
            *p_key_presence |= HAS_SIGHASH_TYPE;
        } else if (keytype == PSBT_IN_BIP32_DERIVATION || keytype == PSBT_IN_TAP_BIP32_DERIVATION) {
            *p_key_presence |= HAS_BIP32_DERIVATION;
        } else if (keytype == PSBT_IN_PROPRIETARY) {
            if (pset_test_key(data, PSBT_ELEMENTS_IN_EXPLICIT_VALUE)) {
                *p_key_presence |= HAS_VALUE;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_EXPLICIT_ASSET)) {
                *p_key_presence |= HAS_ASSET;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_VALUE)) {
                *p_key_presence |= HAS_ISSUANCE_VALUE;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT)) {
                *p_key_presence |= HAS_ISSUANCE_VALUE_COMMITMENT;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF)) {
                *p_key_presence |= HAS_ISSUANCE_BLIND_VALUE_PROOF;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT)) {
                *p_key_presence |= HAS_ISSUANCE_INFLATION_KEYS_AMOUNT;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT)) {
                *p_key_presence |= HAS_ISSUANCE_INFLATION_KEYS_COMMITMENT;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE)) {
                *p_key_presence |= HAS_ISSUANCE_BLINDING_NONCE;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY)) {
                *p_key_presence |= HAS_ISSUANCE_ASSET_ENTROPY;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF)) {
                *p_key_presence |= HAS_ISSUANCE_BLIND_INFLATION_KEYS_PROOF;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_VALUE_PROOF)) {
                *p_key_presence |= HAS_VALUE_PROOF;
            } else if (pset_test_key(data, PSBT_ELEMENTS_IN_ASSET_PROOF)) {
                *p_key_presence |= HAS_ASSET_PROOF;
            }
        }

        buffer_restore(data, snapshot);
    }
}

void pset_detect_output_key(buffer_t *data, uint32_t *p_key_presence) {
    if (!data || !p_key_presence) {
        return;
    }

    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        buffer_snapshot_t snapshot = buffer_snapshot(data);

        uint8_t keytype;
        buffer_read_u8(data, &keytype);

        if (keytype == PSBT_OUT_BIP32_DERIVATION || keytype == PSBT_OUT_TAP_BIP32_DERIVATION) {
            *p_key_presence |= HAS_BIP32_DERIVATION;
        } else if (keytype == PSBT_OUT_AMOUNT) {
            *p_key_presence |= HAS_VALUE;
        } else if (keytype == PSBT_IN_PROPRIETARY) {
            if (pset_test_key(data, PSBT_ELEMENTS_OUT_VALUE_COMMITMENT)) {
                *p_key_presence |= HAS_VALUE_COMMITMENT;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_ASSET)) {
                *p_key_presence |= HAS_ASSET;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_ASSET_COMMITMENT)) {
                *p_key_presence |= HAS_ASSET_COMMITMENT;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF)) {
                *p_key_presence |= HAS_VALUE_RANGEPROOF;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF)) {
                *p_key_presence |= HAS_ASSET_SURJECTION_PROOF;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_BLINDING_PUBKEY)) {
                *p_key_presence |= HAS_BLINDING_PUBKEY;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_ECDH_PUBKEY)) {
                *p_key_presence |= HAS_ECDH_PUBKEY;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_BLINDER_INDEX)) {
                *p_key_presence |= HAS_BLINDER_INDEX;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF)) {
                *p_key_presence |= HAS_VALUE_PROOF;
            } else if (pset_test_key(data, PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF)) {
                *p_key_presence |= HAS_ASSET_PROOF;
            }
        }

        buffer_restore(data, snapshot);
    }
}

#endif  // HAVE_LIQUID
