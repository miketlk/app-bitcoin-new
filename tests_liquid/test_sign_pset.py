import pytest

import json

from pathlib import Path
from collections.abc import Iterable

from bitcoin_client.ledger_bitcoin import BlindedWallet

from bitcoin_client.ledger_bitcoin.pset import PSET
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient
from .instructions import *

from test_utils import SpeculosGlobals

import hmac
from hashlib import sha256

import random
import string

tests_root: Path = Path(__file__).parent


def open_pset_from_file(filename: str) -> PSET:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSET()
    psbt.deserialize(raw_psbt_base64)

    return psbt


def pset_outputs_to_verify(pset: PSET) -> int:
    n_outs = 0
    for o in pset.outputs:
        # Skip fee output and possible balancing output(s) that follow
        if not o.script:
            break

        # Skip change output
        skip = False
        for _, v in o.hd_keypaths.items():
            if len(v.path) >= 4 and v.path[-2] == 1:
                skip = True
                break

        if not skip:
            n_outs += 1

    return n_outs


def random_wallet_name() -> str:
    charset = string.ascii_letters+string.digits
    return "wallet_" + ''.join(random.choice(charset) for i in range(random.randint(2, 16-7)))

def is_sighash_nondef(sighash):
    if isinstance(sighash, int):
        return sighash not in [0, 1]
    else:
        return sighash not in ["DEFAULT", "ALL"]

def test_sign_pset_batch(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals: SpeculosGlobals, enable_slow_tests: bool):
    # A series of tests for various script and sighash combinations.
    # Takes quite a long time. It's recommended to enable stdout to see the progress (pytest -s).
    # For the full test of all combinations run with '--enableslowtests'.

    client.debug = False
    random.seed(1)

    with open(f"{tests_root}/pset/test_data.json", "r") as read_file:
        test_data = json.load(read_file)

    # Loop through all test suites
    for suite_index, (_, suite) in enumerate(test_data["valid"].items()):
        wallet = BlindedWallet(
            name = random_wallet_name(),
            blinding_key = suite["mbk"],
            descriptor_template = suite["policy_map"],
            keys_info = suite["keys_info"]
        )

        # Loop through all tests within a suite
        for test_index, test in enumerate(suite["tests"]):
            print("TEST:", suite["description"], test["description"])

            pset = PSET()
            pset.deserialize(test["pset"])

            result = client.sign_psbt(
                pset,
                wallet,
                hmac.new(speculos_globals.wallet_registration_key, wallet.id, sha256).digest(),
                navigator,
                instructions = liquid_sign_psbt_instruction_approve(
                    firmware,
                    wallet_spend = True,
                    nondef_sighash = 1 if is_sighash_nondef(test["sighash"]) else 0,
                    unknown_assets = 1 if (("asset_tag" in test) and ("asset_contract" not in test)) else 0,
                    assets = 2 if ("asset_contract" in test) else 0,
                    outs = pset_outputs_to_verify(pset),
                    save_screenshots=False
                ),
                testname = f"{test_name}_{suite_index}_{test_index}"
            )

            assert len(result) == len(test["signatures"].items())
            for n_input, sigs in test["signatures"].items():
                assert int(n_input) < len(result)
                n, s = result[int(n_input)]
                assert n == int(n_input)
                result_sig = s.signature.hex()
                assert len(result_sig) >= 100 and len(result_sig) <= 144
                assert result_sig.startswith("304")
                assert result_sig in sigs["final_scriptwitness"]

            # Run only first test from each suite if not executed with '--enableslowtests'
            if not enable_slow_tests:
                break


def test_asset_metadata_display(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, is_speculos: bool):
    # Test correctness of displayed asset ticker and precision when processing PSET with embedded
    # asset metadata.

    if not is_speculos:
        pytest.skip("Requires speculos")

    with open(f"{tests_root}/pset/asset_metadata.json", "r") as read_file:
        test_data = json.load(read_file)["valid"]["wpkh"]

    wallet = BlindedWallet(
        name="",
        blinding_key=test_data["mbk"],
        descriptor_template=test_data["policy_map"],
        keys_info=test_data["keys_info"]
    )

    # Loop through all test vectors
    for index, test_vector in enumerate(test_data["tests"]):
        pset = PSET()
        pset.deserialize(test_vector["pset"])

        result = client.sign_psbt(
            pset, wallet, None, navigator,
            instructions=liquid_sign_psbt_instruction_approve(
                firmware,
                assets=2,
                outs=pset_outputs_to_verify(pset)
            ),
            testname=f"{test_name}_{index}"
        )

        ref_signatures = test_vector["signatures"].items()
        assert len(result) == len(ref_signatures)
        for n_input, sigs in ref_signatures:
            assert int(n_input) < len(result)
            result_n_input, result_sig = result[int(n_input)]
            assert result_n_input == int(n_input)
            assert result_sig.signature.hex() == sigs["final_scriptwitness"][0]
            assert result_sig.pubkey.hex() == sigs["final_scriptwitness"][1]


def test_unknown_asset_display(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, is_speculos: bool):
    # Test correctness of displayed unknown asset information when processing PSET with embedded
    # asset metadata.

    if not is_speculos:
        pytest.skip("Requires speculos")

    with open(f"{tests_root}/pset/unknown_asset.json", "r") as read_file:
        test_data = json.load(read_file)["valid"]["wpkh"]

    wallet = BlindedWallet(
        name="",
        blinding_key=test_data["mbk"],
        descriptor_template=test_data["policy_map"],
        keys_info=test_data["keys_info"]
    )

    # Loop through all test vectors
    for index, test_vector in enumerate(test_data["tests"]):
        pset = PSET()
        pset.deserialize(test_vector["pset"])

        result = client.sign_psbt(
            pset, wallet, None, navigator,
            instructions=liquid_sign_psbt_instruction_approve(
                firmware,
                unknown_assets=1,
                outs=pset_outputs_to_verify(pset)
            ),
            testname = f"{test_name}_{index}"
        )
        index += 1

        ref_signatures = test_vector["signatures"].items()
        assert len(result) == len(ref_signatures)
        for n_input, sigs in ref_signatures:
            assert int(n_input) < len(result)
            result_n_input, result_sig = result[int(n_input)]
            assert result_n_input == int(n_input)
            assert result_sig.signature.hex() == sigs["final_scriptwitness"][0]
            assert result_sig.pubkey.hex() == sigs["final_scriptwitness"][1]


def test_asset_operations(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, is_speculos: bool):
    # Test correct signing of asset reissuance transaction.

    client.debug = False
    random.seed(1)

    with open(f"{tests_root}/pset/asset_operations.json", "r") as read_file:
        test_data = json.load(read_file)

    # Loop through all test suites
    for suite_index, (_, suite) in enumerate(test_data["valid"].items()):
        wallet = BlindedWallet(
            name="",
            blinding_key=suite["mbk"],
            descriptor_template=suite["policy_map"],
            keys_info=suite["keys_info"]
        )

        # Loop through all tests within a suite
        for test_index, test in enumerate(suite["tests"]):
            print("TEST:", suite["description"], test["description"])

            pset = PSET()
            pset.deserialize(test["pset"])

            result = client.sign_psbt(
                pset, wallet, None, navigator,
                instructions=liquid_sign_psbt_instruction_approve(
                    firmware,
                    assets=1,
                    outs=pset_outputs_to_verify(pset)
                ),
                testname = f"{test_name}_{suite_index}_{test_index}"
            )

            ref_signatures = test["signatures"].items()
            assert len(result) == len(ref_signatures)
            for n_input, sigs in ref_signatures:
                assert int(n_input) < len(result)
                result_n_input, result_sig = result[int(n_input)]
                assert result_n_input == int(n_input)
                assert result_sig.signature.hex() == sigs["final_scriptwitness"][0]
                assert result_sig.pubkey.hex() == sigs["final_scriptwitness"][1]

def test_sighash_flags(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals: SpeculosGlobals):
    # Tests for correctness of sighash display

    client.debug = False
    random.seed(1)

    with open(f"{tests_root}/pset/sighash_flags.json", "r") as read_file:
        test_data = json.load(read_file)

    # Loop through all test suites
    for suite_index, (_, suite) in enumerate(test_data["valid"].items()):
        wallet = BlindedWallet(
            name = "",
            blinding_key = suite["mbk"],
            descriptor_template = suite["policy_map"],
            keys_info = suite["keys_info"]
        )

        # Loop through all tests within a suite
        for test_index, test in enumerate(suite["tests"]):
            print("TEST:", suite["description"], test["description"])

            pset = PSET()
            pset.deserialize(test["pset"])

            result = client.sign_psbt(
                pset,
                wallet,
                None,
                navigator,
                instructions = liquid_sign_psbt_instruction_approve(
                    firmware,
                    nondef_sighash = 1
                ),
                testname = f"{test_name}_{suite_index}_{test_index}"
            )

            assert len(result) == len(test["signatures"].items())
            for n_input, sigs in test["signatures"].items():
                assert int(n_input) < len(result)
                n, s = result[int(n_input)]
                assert n == int(n_input)
                result_sig = s.signature.hex()
                assert len(result_sig) >= 100 and len(result_sig) <= 144
                assert result_sig.startswith("304")
                assert result_sig in sigs["final_scriptwitness"]

def test_sighashes_multi_input(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, is_speculos: bool):
    # Test correctness of displayed asset ticker and precision when processing PSET with embedded
    # asset metadata.

    with open(f"{tests_root}/pset/sighashes_multi_input.json", "r") as read_file:
        test_data = json.load(read_file)["valid"]["wpkh"]

    wallet = BlindedWallet(
        name="",
        blinding_key=test_data["mbk"],
        descriptor_template=test_data["policy_map"],
        keys_info=test_data["keys_info"]
    )

    # Loop through all test vectors
    for index, test_vector in enumerate(test_data["tests"]):
        pset = PSET()
        pset.deserialize(test_vector["pset"])

        # Multiple sighashes are expected for this test
        assert isinstance(test_vector["sighash"], Iterable)

        result = client.sign_psbt(
            pset, wallet, None, navigator,
            instructions=liquid_sign_psbt_instruction_approve(
                firmware,
                nondef_sighash=sum(is_sighash_nondef(sh) for sh in test_vector["sighash"]),
                outs=pset_outputs_to_verify(pset)
            ),
            testname=f"{test_name}_{index}"
        )

        ref_signatures = test_vector["signatures"].items()
        if ref_signatures:
            assert len(result) == len(ref_signatures)
            for n_input, sigs in ref_signatures:
                assert int(n_input) < len(result)
                result_n_input, result_sig = result[int(n_input)]
                assert result_n_input == int(n_input)
                assert result_sig.signature.hex() == sigs["final_scriptwitness"][0]
                assert result_sig.pubkey.hex() == sigs["final_scriptwitness"][1]