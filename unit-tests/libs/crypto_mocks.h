// We're currently unable to compile the app's crypto.c in unit tests.
// This library mocks the functions currently used in other modules that are part of
// the unit tests.

#include <stdint.h>

#ifdef HAVE_LIQUID
/// Version bytes of Liquid regtest xpub
#define LIQUID_REGTEST_XPUB 0x043587CF
/// Version bytes of Liquid regtest xprv
#define LIQUID_REGTEST_XPRV 0x04358394
/// Version bytes of Liquid main network (liquidv1) xpub
#define LIQUID_MAIN_XPUB 0x0488B21E
/// Version bytes of Liquid main network (liquidv1) xprv
#define LIQUID_MAIN_XPRV 0x0488ADE4

/// Mock BIP32_PUBKEY_VERSION preprocessor definition making it mutable
extern uint32_t BIP32_PUBKEY_VERSION;
/// Mock BIP32_PRIVKEY_VERSION preprocessor definition making it mutable
extern uint32_t BIP32_PRIVKEY_VERSION;
#endif  // HAVE_LIQUID

void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]);