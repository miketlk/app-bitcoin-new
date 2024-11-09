# ****************************************************************************
#    Ledger App for Bitcoin
#    (c) 2024 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifndef DEBUG_LOG_LEVEL
    ifdef DEBUG
        DEBUG_LOG_LEVEL := $(DEBUG)
    else
        DEBUG_LOG_LEVEL := 0
    endif
endif

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

# TODO: Compile with the right path restrictions
#
#       The right path restriction would be something like
#         --path "*'/0'"
#       for mainnet, and
#         --path "*'/1'"
#       for testnet.
#
#       That is, restrict the BIP-44 coin_type, but not the purpose.
#       However, such wildcards are not currently supported by the OS.
#
#       Note that the app still requires explicit user approval before exporting
#       any xpub outside of a small set of allowed standard paths.

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS = secp256k1

# Application allowed derivation paths.
#
#       If there would be a dedicated SDK function returning master key
#       fingerprint without the need to derive the root pubkey, the proper path
#       configuration should be:
#
#       PATH_APP_LOAD_PARAMS = "44'/1'" "48'/1'" "49'/1'" "84'/1'" "86'/1'"
#
PATH_APP_LOAD_PARAMS = ""

# Allowed SLIP21 paths
PATH_SLIP21_APP_LOAD_PARAMS = "LEDGER-Wallet policy"

# Application version
APPVERSION_M = 2
APPVERSION_N = 2
APPVERSION_P = 3
APPVERSION_SUFFIX = # if not empty, appended at the end. Do not add a dash.

ifeq ($(APPVERSION_SUFFIX),)
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"
else
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)-$(strip $(APPVERSION_SUFFIX))"
endif

# simplify for tests
ifndef COIN
COIN=liquid_regtest
endif

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = bitcoin_testnet bitcoin liquid_regtest liquid

########################################
#     Application custom permissions   #
########################################
HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
ifneq (,$(findstring bitcoin,$(COIN)))
HAVE_APPLICATION_FLAG_LIBRARY = 1
endif


ifeq ($(COIN),bitcoin_testnet)

# Bitcoin testnet, no legacy support
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=196
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tb\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"

APPNAME = "Bitcoin Test"
DISPLAYED_APPNAME = "Bitcoin Testnet"

else ifeq ($(COIN),bitcoin)

# Bitcoin mainnet, no legacy support
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += COIN_P2PKH_VERSION=0
DEFINES   += COIN_P2SH_VERSION=5
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bc\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"

APPNAME = "Bitcoin"

else ifeq ($(COIN),liquid_regtest)

# Liquid regtest
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP32_PRIVKEY_VERSION=0x04358394
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=75
DEFINES   += COIN_PREFIX_CONFIDENTIAL=4
DEFINES   += HAVE_LIQUID
DEFINES   += HAVE_LIQUID_TEST
DEFINES   += COIN_BLINDED_VERSION=4
DEFINES   += COIN_COINID_SHORT=\"L-BTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"ert\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL=\"el\"

APPNAME = "Liquid Regtest"

else ifeq ($(COIN),liquid)

# Liquid
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP32_PRIVKEY_VERSION=0x0488ADE4
DEFINES   += BIP44_COIN_TYPE=1776
DEFINES   += COIN_P2PKH_VERSION=57
DEFINES   += COIN_P2SH_VERSION=39
DEFINES   += COIN_PREFIX_CONFIDENTIAL=12
DEFINES   += HAVE_LIQUID
DEFINES   += COIN_BLINDED_VERSION=12
DEFINES   += COIN_COINID_SHORT=\"L-BTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"ex\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL=\"lq\"

APPNAME = "Liquid"

else
ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use bitcoin_testnet, bitcoin, liquid_regtest, liquid)
endif
endif

ifneq (,$(findstring liquid,$(COIN)))
# Add the second SLIP-0021 path for the SLIP-0077 derivation.
# HACK: Using '--path_slip21' is a temporary solution due to lack of support for
# multiple SLIP-0021 path entries in the SDK.
PATH_SLIP21_APP_LOAD_PARAMS += --path_slip21 "SLIP-0077"
endif

ifdef DISPLAYED_APPNAME
CFLAGS += -DDISPLAYED_APPNAME=\"$(DISPLAYED_APPNAME)\"
else
CFLAGS += -DDISPLAYED_APPNAME=\"$(APPNAME)\"
endif

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon

ifneq (,$(findstring bitcoin,$(COIN)))
# Bitcoin icons
ICON_NANOS = icons/nanos_app_bitcoin.gif
ICON_NANOX = icons/nanox_app_bitcoin.gif
ICON_NANOSP = icons/nanox_app_bitcoin.gif
ICON_STAX = icons/stax_app_bitcoin.gif
else ifneq (,$(findstring liquid,$(COIN)))
# Liquid icons
ICON_NANOS = icons/nanos_app_liquid.gif
ICON_NANOX = icons/nanox_app_liquid.gif
ICON_NANOSP = icons/nanox_app_liquid.gif
ICON_STAX = icons/stax_app_liquid.gif
else
$(error Unsupported COIN)
endif

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1

########################################
#          Features disablers          #
########################################
# Don't use standard app file to avoid conflicts for now
DISABLE_STANDARD_APP_FILES = 1

# Don't use default IO_SEPROXY_BUFFER_SIZE to use another
# value for NANOS for an unknown reason.
DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1

DEFINES   += HAVE_BOLOS_APP_STACK_CANARY

ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=72
DEFINES       += HAVE_WALLET_ID_SDK
else
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=300
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
    # enables optimizations using the shared 1K CXRAM region
    DEFINES   += USE_CXRAM_SECTION
    # enables usage of the NVRAM to free up some RAM
    DEFINES   += USE_NVRAM_STASH
endif

# debugging helper functions and macros
CFLAGS    += -include debug-helpers/debug.h

# DEFINES += HAVE_PRINT_STACK_POINTER
# DEFINES += HAVE_LOG_PROCESSOR
# DEFINES += HAVE_APDU_LOG
DEFINES += DEBUG_LOG_LEVEL=$(DEBUG_LOG_LEVEL)

ifeq ($(TEST),1)
    $(warning On-device tests should only be run with Speculos!)
    DEFINES += RUN_ON_DEVICE_TESTS HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF
else ifeq ($(DEBUG_LOG_LEVEL),10)
    $(warning Using semihosted PRINTF. Only run with speculos!)
    DEFINES += HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF
else ifeq ($(DEBUG_LOG_LEVEL),11)
    $(warning CCMD PRINTF is used! APDU exchage is affected.)
    DEFINES += HAVE_CCMD_PRINTF
endif

# Needed to be able to include the definition of G_cx
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

# Application source files
APP_SOURCE_PATH += src

# Allow usage of function from lib_standard_app/crypto_helpers.c
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/crypto_helpers.c

include $(BOLOS_SDK)/Makefile.standard_app

# Makes a detailed report of code and data size in debug/size-report.txt
# More useful for production builds with DEBUG=0
size-report: bin/app.elf
	arm-none-eabi-nm --print-size --size-sort --radix=d bin/app.elf >debug/size-report.txt
