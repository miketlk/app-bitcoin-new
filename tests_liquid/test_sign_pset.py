import pytest

import threading

import json

from decimal import Decimal

from typing import List

from pathlib import Path

from bitcoin_client.ledger_bitcoin import Client, BlindedWallet, BlindedMultisigWallet, AddressType
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError

from bitcoin_client.ledger_bitcoin.pset import PSET
from bitcoin_client.ledger_bitcoin.wallet import AddressType
from speculos.client import SpeculosClient

from test_utils import has_automation, bip0340, txmaker, mnemonic, SpeculosGlobals

from embit.script import Script
from embit.networks import NETWORKS

from test_utils.speculos import automation

import hmac
from hashlib import sha256

import random
import string

tests_root: Path = Path(__file__).parent


def format_amount(ticker: str, amount: int, precision: int = 8) -> str:
    """Formats an amounts in sats as shown in the app: divided by 10_000_000, with no trailing zeroes."""
    assert amount >= 0

    return f"{ticker} {str(Decimal(amount) / (10**precision))}"


def should_go_right(event: dict):
    """Returns true if the current text event implies a "right" button press to proceed."""

    if event["text"].startswith("Review"):
        return True
    elif event["text"].startswith("Amount"):
        return True
    elif event["text"].startswith("Asset tag"):
        return True
    elif event["text"].startswith("Address"):
        return True
    elif event["text"].startswith("Confirm"):
        return True
    elif event["text"].startswith("Fees"):
        return True
    elif event["text"].startswith("Asset name"):
        return True
    elif event["text"].startswith("Asset domain"):
        return True
    elif event["text"].startswith("The asset"):
        return True
    elif event["text"].startswith("Reject"):
        return True
    return False


def ux_thread_sign_pset(speculos_client: SpeculosClient, all_events: List[dict]):
    """Completes the signing flow always going right and accepting at the appropriate time, while collecting all the events in all_events."""

    # press right until the last screen (will press the "right" button more times than needed)

    while True:
        event = speculos_client.get_next_event()
        all_events.append(event)

        if should_go_right(event):
            speculos_client.press_and_release("right")
        elif event["text"] == "Approve":
            speculos_client.press_and_release("both")
        elif event["text"] == "Continue":
            speculos_client.press_and_release("both")
        elif event["text"] == "Accept":
            speculos_client.press_and_release("both")
            break


def parse_signing_events(events: List[dict]) -> dict:
    ret = dict()

    # each of these is True if the _previous_ event was matching (so the next text needs to be recorded)
    was_amount = False
    was_address = False
    was_asset = False
    was_fees = False

    section = None
    prev_text = []

    cur_output_index = -1

    ret["addresses"] = []
    ret["amounts"] = []
    ret["unknown_assets"] = []
    ret["assets"] = []
    ret["fees"] = ""

    for ev in events:
        if ( not section and ev["text"].startswith("Asset tag") and len(prev_text) >= 2 and
            prev_text[-1] == "is unknown" and prev_text[-2] == "The asset" ):
            section = 'unknown_asset'
            ret["unknown_assets"].append("")
        elif ev["text"].startswith("output #"):
            section = 'output'
            idx_str = ev["text"][8:]

            assert int(idx_str) - 1 == cur_output_index + 1  # should not skip outputs

            cur_output_index = int(idx_str) - 1

            ret["addresses"].append("")
            ret["amounts"].append("")
            ret["assets"].append("")

        if section == 'output':
            if was_address:
                ret["addresses"][-1] += ev["text"]
            if was_amount:
                ret["amounts"][-1] += ev["text"]
            if was_asset:
                ret["assets"][-1] += ev["text"]
            if was_fees:
                ret["fees"] += ev["text"]
        elif section == 'unknown_asset':
            if len(prev_text) >= 2 and prev_text[-1].startswith("Asset tag"):
                ret["unknown_assets"][-1] += ev["text"]
            elif not ev["text"].startswith("Asset tag"):
                section = None

        was_amount = ev["text"].startswith("Amount")
        was_address = ev["text"].startswith("Address")
        was_asset = ev["text"].startswith("Asset tag")
        was_fees = ev["text"].startswith("Fees")
        prev_text.append(ev["text"])

    return ret


def open_pset_from_file(filename: str) -> PSET:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSET()
    psbt.deserialize(raw_psbt_base64)

    return psbt


def random_wallet_name() -> str:
    charset = string.ascii_letters+string.digits
    return "wallet_" + ''.join(random.choice(charset) for i in range(random.randint(2, 16-7)))


@pytest.mark.skip(reason="not supported yet")
@has_automation(f"{tests_root}/automations/sign_with_any_wallet_accept.json")
def test_sign_psbt_batch(client: Client, speculos_globals: SpeculosGlobals, is_speculos: bool, enable_slow_tests: bool):
    # A series of tests for various script and sighash combinations.
    # Takes quite a long time. It's recommended to enable stdout to see the progress (pytest -s).
    # For the full test of all combinations run with '--enableslowtests'.

    client.debug = False
    random.seed(1)

    with open(f"{tests_root}/pset/test_data.json", "r") as read_file:
        test_data = json.load(read_file)

    # Loop through all test suites
    for _, suite in test_data["valid"].items():
        wallet = BlindedWallet(
            name=random_wallet_name(),
            blinding_key=suite["mbk"],
            descriptor_template=suite["policy_map"],
            keys_info=suite["keys_info"]
        )

        wallet_hmac = None
        if len(suite["keys_info"]) > 1:
            # Register wallet before multisig tests
            wallet_id, wallet_hmac = client.register_wallet(wallet, sanity_check=False)
            assert wallet_id == wallet.id
            assert hmac.compare_digest(
                hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
                wallet_hmac,
            )

        # Loop through all tests within a suite
        for test in suite["tests"]:
            print("TEST:", suite["description"], test["description"])

            pset = PSET()
            pset.deserialize(test["pset"])
            result = client.sign_psbt(pset, wallet, wallet_hmac)

            for n_input, sigs in test["signatures"].items():
                result_sig = result[int(n_input)].hex()
                assert len(result_sig) >= 100 and len(result_sig) <= 144
                assert result_sig.startswith("304")
                assert result_sig in sigs["final_scriptwitness"]

            # Run only first test from each suite if not executed with '--enableslowtests'
            if not enable_slow_tests:
                break

@pytest.mark.skip(reason="not supported yet")
def test_asset_metadata_display(client: Client, comm: SpeculosClient, is_speculos: bool):
    # Test correctness of displayed asset ticker and precision when processing PSET with embedded
    # asset metadata.

    if not is_speculos:
        pytest.skip("Requires speculos")

    with open(f"{tests_root}/pset/asset_metadata.json", "r") as read_file:
        test_data = json.load(read_file)["valid"]["wpkh"]

    wallet = BlindedWallet(
        name="Cold storage",
        blinding_key=test_data["mbk"],
        descriptor_template="wpkh(@0)",
        keys_info=test_data["keys_info"]
    )

    # Loop through all test vectors
    for test_vector in test_data["tests"]:
        pset = PSET()
        pset.deserialize(test_vector["pset"])
        contract = json.loads(test_vector["asset_contract"])

        all_events: List[dict] = []
        x = threading.Thread(target=ux_thread_sign_pset, args=[comm, all_events])
        x.start()
        result = client.sign_psbt(pset, wallet, wallet_hmac=None)
        x.join()
        parsed_events = parse_signing_events(all_events)

        assert len(parsed_events["addresses"]) == 1
        assert parsed_events["addresses"][0] == test_vector["destination_address"]["unconfidential"]
        assert len(parsed_events["amounts"]) == 1
        assert parsed_events["amounts"][0] == format_amount(contract["ticker"], test_vector["amount"], contract["precision"])
        assert parsed_events["fees"] == format_amount("TL-BTC", test_vector["fee"])
        assert len(parsed_events["assets"]) == 1
        assert parsed_events["assets"][0].lower() == test_vector["asset_tag"]

        for n_input, sigs in test_vector["signatures"].items():
            result_sig = result[int(n_input)].hex()
            assert len(result_sig) >= 100 and len(result_sig) <= 144
            assert result_sig.startswith("304")
            assert result_sig in sigs["final_scriptwitness"]

@pytest.mark.skip(reason="not supported yet")
def test_unknown_asset_display(client: Client, comm: SpeculosClient, is_speculos: bool):
    # Test correctness of displayed unknown asset information when processing PSET with embedded
    # asset metadata.

    if not is_speculos:
        pytest.skip("Requires speculos")

    with open(f"{tests_root}/pset/unknown_asset.json", "r") as read_file:
        test_data = json.load(read_file)["valid"]["wpkh"]

    wallet = BlindedWallet(
        name="Cold storage",
        blinding_key=test_data["mbk"],
        descriptor_template="wpkh(@0)",
        keys_info=test_data["keys_info"]
    )

    # Loop through all test vectors
    for test_vector in test_data["tests"]:
        pset = PSET()
        pset.deserialize(test_vector["pset"])

        all_events: List[dict] = []
        x = threading.Thread(target=ux_thread_sign_pset, args=[comm, all_events])
        x.start()
        result = client.sign_psbt(pset, wallet, wallet_hmac=None)
        x.join()

        parsed_events = parse_signing_events(all_events)

        assert len(parsed_events["amounts"]) == 1
        assert parsed_events["amounts"][0] == format_amount("???", test_vector["amount"], 0)
        assert parsed_events["fees"] == format_amount("TL-BTC", test_vector["fee"])
        assert len(parsed_events["unknown_assets"]) == 1
        assert parsed_events["unknown_assets"][0].lower() == test_vector["asset_tag"]
        assert len(parsed_events["assets"]) == 1
        assert parsed_events["assets"][0].lower() == test_vector["asset_tag"]

        for n_input, sigs in test_vector["signatures"].items():
            result_sig = result[int(n_input)].hex()
            assert len(result_sig) >= 100 and len(result_sig) <= 144
            assert result_sig.startswith("304")
            assert result_sig in sigs["final_scriptwitness"]

@pytest.mark.skip(reason="not supported yet")
@has_automation(f"{tests_root}/automations/sign_with_any_wallet_accept.json")
def test_asset_operations(client: Client, is_speculos: bool):
    # Test correct signing of asset reissuance transaction.

    client.debug = False
    random.seed(1)

    with open(f"{tests_root}/pset/asset_operations.json", "r") as read_file:
        test_data = json.load(read_file)

    # Loop through all test suites
    for _, suite in test_data["valid"].items():
        wallet = BlindedWallet(
            name=random_wallet_name(),
            blinding_key=suite["mbk"],
            descriptor_template=suite["policy_map"],
            keys_info=suite["keys_info"]
        )

        # Loop through all tests within a suite
        for test in suite["tests"]:
            print("TEST:", suite["description"], test["description"])

            pset = PSET()
            pset.deserialize(test["pset"])
            result = client.sign_psbt(pset, wallet, None)

            for n_input, sigs in test["signatures"].items():
                result_sig = result[int(n_input)].hex()
                assert len(result_sig) >= 100 and len(result_sig) <= 144
                assert result_sig.startswith("304")
                assert result_sig in sigs["final_scriptwitness"]
