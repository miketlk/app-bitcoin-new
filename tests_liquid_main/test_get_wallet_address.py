from bitcoin_client.ledger_bitcoin import Client, AddressType, MultisigWallet, PolicyMapWallet, BlindedWallet, BlindedMultisigWallet
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError

import random
import string
import json
from pathlib import Path

import pytest

tests_root: Path = Path(__file__).parent

def random_wallet_name() -> str:
    charset = string.ascii_letters+string.digits
    return "wallet_" + ''.join(random.choice(charset) for i in range(random.randint(2, 16-7)))

def test_get_wallet_address_elip150_batch(client: Client, speculos_globals):
    # Ensure the tests are repeatable
    random.seed(1)

    with open(f"{tests_root}/wallets/wallets_elip150.json", "r") as read_file:
        test_data = json.load(read_file)

    # Loop through all test suites with valid vectors
    for test in test_data["valid"]:
        # Test confidential address
        wallet = BlindedWallet(
            name=random_wallet_name(),
            blinding_key=test["blinding_key"],
            policy_map=test["policy_map"],
            keys_info=test["keys_info"]
        )
        res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
        assert res == test["confidential_address"]

        # Test unconfidential address
        wallet = PolicyMapWallet(
            name=random_wallet_name(),
            policy_map=test["policy_map"],
            keys_info=test["keys_info"]
        )
        res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
        assert res == test["unconfidential_address"]

    # Loop through all test suites with invalid vectors
    for test in test_data["invalid"]:
        # Test confidential address
        wallet = BlindedWallet(
            name=random_wallet_name(),
            blinding_key=test["blinding_key"],
            policy_map=test["policy_map"],
            keys_info=test["keys_info"]
        )
        with pytest.raises(IncorrectDataError):
            client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)

def test_get_wallet_address_elip151_singlesig_elwpkh_standard_chains(client: Client, speculos_globals):
    # ELIP 151: Test vector 1
    # ct(elip151,elwpkh(xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8/<0;1>/*))#m47kvl05
    wallet = BlindedWallet(
        name="",
        blinding_key="elip151",
        policy_map="elwpkh(@0)",
        keys_info=[
            "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8/<0;1>/*",
        ],
    )

    res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
    assert res == "lq1qqt33kuqusp3amjam96zxg27wvg2ewvl69h3equtck8lk8349vrxt28w2wqel8nstvtmefmexkn9zg5hhku2u7kr9k068fk338"

def test_get_wallet_address_elip151_singlesig_elwpkh_external_chain(client: Client, speculos_globals):
    # ELIP 151: Test vector 2
    # ct(elip151,elwpkh(xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8/0/*))#y0su9u33
    wallet = BlindedWallet(
        name="",
        blinding_key="elip151",
        policy_map="elwpkh(@0)",
        keys_info=[
            "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8/0/*",
        ],
    )

    res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
    assert res == "lq1qqwv7x220qlm8kwjewuwcdl2c88n202jx4ug7fhjdj3xt25my2zq0w8w2wqel8nstvtmefmexkn9zg5hhku2u7gc263jye380e"

def test_get_wallet_address_elip151_multisig_elwpkh_standard_chains(client: Client, speculos_globals):
    # ELIP 151: Test vector 3
    # ct(elip151,elwsh(multi(2,xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8/<0;1>/*,
    #                          xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/<0;1>/*)))#0xa8n98p
    wallet = BlindedMultisigWallet(
        name="",
        blinding_key="elip151",
        address_type=AddressType.WIT,
        threshold=2,
        sorted=False,
        keys_info=[
            "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8/<0;1>/*",
            "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/<0;1>/*"
        ],
    )

    res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
    assert res == "lq1qqtpv5u879fm7v20hv57x4x4kr986j74n5sranvq6wsacvwawyehx0a9t8tdqwj79lhuu94fr2a7hu4nacs5dgufsrfycfguwqg809stvl2vxv30uam4m"