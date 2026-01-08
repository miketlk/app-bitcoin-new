#!/bin/bash

# liquid-update-snapshots.sh
# Update reference display snapshots for all devices and Liquid build configurations

set -e  # Exit on error unless explicitly handled

# Define colors and styles for output
BOLD='\033[1m'
TEAL='\033[0;36m'
GREEN='\033[1;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color, no style

# Ensure the script is running inside a Python virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${RED}${BOLD}Error: This script must be run inside a Python virtual environment. Please activate your virtual environment and try again.${NC}"
    exit 1
fi

# Ensure the script is run from the correct directory
LEDGER_APP_TOML="ledger_app.toml"
if [ ! -f $LEDGER_APP_TOML ]; then
    echo -e "${RED}${BOLD}Error: ledger_app.toml not found. Please run this script from the project root directory.${NC}"
    exit 1
fi

# Map from coin to test directory
COIN_TO_TESTDIR_KEYS=("liquid_regtest" "liquid_testnet" "liquid")
COIN_TO_TESTDIR_VALUES=("tests_liquid" "tests_liquid_testnet" "tests_liquid_main")

# Map from device to SDK key and value
DEVICE_TO_SDK_KEYS=("nanos" "nanosp" "nanox")
DEVICE_TO_SDK_VALUES=("NANOS_SDK" "NANOSP_SDK" "NANOX_SDK")

# Extract DEVICES from ledger_app.toml, replacing "nanos+" with "nanosp"
DEVICES=($(grep -E 'devices = \[.*\]' "$LEDGER_APP_TOML" | sed -E 's/devices = \[(.*)\]/\1/' | tr -d '"' | tr ',' '\n' | sed 's/nanos+/nanosp/'))

# Extract COINS from VARIANT_VALUES in the Makefile
MAKEFILE_PATH="Makefile"
COINS=($(grep -E '^VARIANT_VALUES\s*=' "$MAKEFILE_PATH" | awk -F'= ' '{print $2}' | tr ' ' '\n'))

# Function to get value from a plain array "map"
get_value_from_map() {
    local key="$1"
    local keys=("${!2}")
    local values=("${!3}")
    for i in "${!keys[@]}"; do
        if [[ "${keys[$i]}" == "$key" ]]; then
            echo "${values[$i]}"
            return
        fi
    done
    echo ""
}

SUMMARY=()

LATEST_VERSION=$(grep -E '^## \[[0-9]+\.[0-9]+\.[0-9]+' CHANGELOG.md | head -n 1 | sed -E 's/^## \[([0-9]+\.[0-9]+\.[0-9]+)\].*/\1/')
echo -e "${TEAL}${BOLD}Using latest version: ${GREEN}${LATEST_VERSION}${NC}"

# Print obtained DEVICES and COINS
echo -e "${TEAL}${BOLD}Devices: ${GREEN}${DEVICES[@]}${NC}"
echo -e "${TEAL}${BOLD}Coins: ${GREEN}${COINS[@]}${NC}"

# Stop any running simulator instance from a previous run
echo -e "Stopping any existing simulator instance..."
docker stop SPECULOS_SIM > /dev/null 2>&1 || true
sleep 3

# Loop through each coin and device combination
echo -e "Building and testing all configurations..."

for COIN in "${COINS[@]}"; do
    TESTDIR=$(get_value_from_map "$COIN" COIN_TO_TESTDIR_KEYS[@] COIN_TO_TESTDIR_VALUES[@])
    if [ -z "$TESTDIR" ]; then
        echo -e "${YELLOW}${BOLD}No test directory defined for $COIN. Skipping...${NC}"
        continue
    fi

    for DEVICE in "${DEVICES[@]}"; do
        SDK=$(get_value_from_map "$DEVICE" DEVICE_TO_SDK_KEYS[@] DEVICE_TO_SDK_VALUES[@])
        if [ -z "$SDK" ]; then
            echo -e "${YELLOW}${BOLD}No SDK found for $DEVICE. Skipping...${NC}"
            continue
        fi

        CONFIG_NAME="$COIN / $DEVICE"

        echo -e "${TEAL}${BOLD}=== Cleaning build for $CONFIG_NAME ===${NC}"
        docker exec -it app-bitcoin-new-container bash -c 'make -C ./ clean'

        echo -e "${TEAL}${BOLD}=== Building for $CONFIG_NAME ===${NC}"
        BUILD_LOG=$(mktemp)
        if docker exec -it app-bitcoin-new-container bash -c "export BOLOS_SDK=\${$SDK} && make -C ./ -B -j COIN=$COIN" >"$BUILD_LOG" 2>&1; then
            BUILD_RESULT="✅ Build OK"
        else
            if grep -q "ImportError: cannot import name 'Buffer' from 'typing_extensions'" "$BUILD_LOG" || \
               grep -q "cp: cannot stat 'build/nanos/bin/app.apdu'" "$BUILD_LOG"; then
                echo "⚠️ Known Docker-related issue detected. Ignoring and continuing..."
                BUILD_RESULT="⚠️ Build has known issue"
            else
                echo -e "${RED}${BOLD}❌ Build failed due to an unknown issue. Stopping.${NC}\n--- Begin Build Log ---"
                cat "$BUILD_LOG"
                echo "--- End Build Log ---"
                rm "$BUILD_LOG"
                exit 1
            fi
        fi
        rm "$BUILD_LOG"

        echo -e "${TEAL}${BOLD}=== Starting simulator for $CONFIG_NAME ===${NC}"
        docker run \
            --rm \
            -d \
            --name SPECULOS_SIM \
            -v "$(pwd)/bin:/speculos/apps" \
            -p 1234:1234 -p 5000:5000 -p 5001:5001 -p 9999:9999 -p 40000:40000 \
            -e SPECULOS_APPNAME="Liquid:${LATEST_VERSION}" \
            ghcr.io/ledgerhq/speculos:latest \
            --seed "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin" \
            --model "$DEVICE" \
            --api-port 5000 \
            --apdu-port 5001 \
            --display headless \
            apps/app.elf

        echo "Waiting for simulator to initialize..."
        sleep 5

        echo -e "${TEAL}${BOLD}=== Running golden snapshot tests for $CONFIG_NAME ===${NC}"
        pushd "$TESTDIR" > /dev/null
        if pytest -W ignore::DeprecationWarning --device "$DEVICE" --speculos_api_port 5000 --golden_run; then
            TEST_RESULT="✅ Snapshots Updated"
        else
            TEST_RESULT="❌ Snapshot Update Failed"
        fi
        popd > /dev/null

        echo "Stopping simulator..."
        docker stop SPECULOS_SIM > /dev/null
        sleep 3

        SUMMARY+=("$CONFIG_NAME → $BUILD_RESULT / $TEST_RESULT")
        echo
    done
done

echo -e "${TEAL}${BOLD}========== SNAPSHOT UPDATE SUMMARY ==========${NC}"
for RESULT in "${SUMMARY[@]}"; do
    echo "$RESULT"
done
