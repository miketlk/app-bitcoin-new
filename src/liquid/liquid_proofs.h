/**
 * Support of lightweight asset/value proofs for Liquid Network
 */

#pragma once
#ifdef HAVE_LIQUID

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include "liquid.h"

/// Maximum length of proof in bytes
#define LIQUID_MAX_VALUE_PROOF_LEN 73
/// Maximum length of a single surjection proof in bytes
#define LIQUID_MAX_SINGLE_SURJECTION_PROOF_LEN 67

/// Alternative generator for secp256k1
extern const uint8_t secp256k1_generator_h[LIQUID_GENERATOR_LEN];
/// Maximum allowed value for scalar
extern const uint8_t secp256k1_scalar_max[32];

/**
 * Verifies a rangeproof with a single-value range
 *
 * @param[in] proof
 *   Pointer to character array with the proof.
 * @param[in] plen
 *   Length of proof in bytes.
 * @param[in] value
 *   Value being claimed for the Pedersen commitment.
 * @param[in] commit
 *   The Pedersen commitment whose value is being proven.
 * @param[in] commit_len
 *   Length of commit in bytes.
 * @param[in] generator
 *   Additional generator 'h' encoded as: 04 x y, where x and y are encoded as big endian raw value.
 *
 * @return true if proof was valid and proved the given value, false otherwise
 */
WARN_UNUSED_RESULT bool liquid_rangeproof_verify_exact(
    const uint8_t *proof,
    size_t plen,
    uint64_t value,
    const uint8_t *commit,
    size_t commit_len,
    const uint8_t generator[static LIQUID_GENERATOR_LEN]);

/**
 * Parses a 33-byte generator byte sequence into a generator object
 *
 * Generator is encoded as: 04 x y, where x and y are encoded as big endian raw value.
 *
 * @param[out] generator
 *    Pointer to 65-byte buffer receiving parsed generator.
 * @param[in] input
 *    Input byte sequence, 33 bytes.
 *
 * @return true if generator parsed successfully
 */
WARN_UNUSED_RESULT bool liquid_generator_parse(uint8_t generator[static LIQUID_GENERATOR_LEN],
                                               const uint8_t input[static LIQUID_COMMITMENT_LEN]);

/**
 * Verifies a single-input surjectionproof
 *
 * @param[in] proof
 *   Pointer to character array with the proof to be verified.
 * @param[in] plen
 *   Length of proof in bytes.
 * @param[in] input_tag
 *   The ephemeral asset tag of the sole input, a curve point encoded as 04 x y.
 * @param[in] output_tag
 *   The ephemeral asset tag of the output, a curve point encoded as 04 x y.
 *
 * @return true if proof was valid, false otherwise
 */
WARN_UNUSED_RESULT bool liquid_surjectionproof_verify_single(
    const uint8_t *proof,
    size_t plen,
    const uint8_t input_tag[static LIQUID_GENERATOR_LEN],
    const uint8_t output_tag[static LIQUID_GENERATOR_LEN]);

/**
 * Generates a generator for the curve.
 *
 * @param[out] gen
 *   Buffer receiving produced generator encoded as: 04 x y.
 * @param[in] seed32_reversed
 *   A 32-byte seed in reverse byte order ("display" byte order for asset tags).
 *
 * @return false in the highly unlikely case the seed is not acceptable, true otherwise
 */
WARN_UNUSED_RESULT bool liquid_generator_generate(uint8_t gen[static LIQUID_GENERATOR_LEN],
                                                  const uint8_t seed32_reversed[static 32]);

#endif  // HAVE_LIQUID