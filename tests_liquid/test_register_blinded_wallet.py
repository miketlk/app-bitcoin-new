from ledger_bitcoin import AddressType, BlindedWallet, BlindedMultisigWallet, WalletPolicy
from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.exception import DenyError
from ragger.navigator import Navigator, NavInsID
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU
from ragger_bitcoin import RaggerClient

from .instructions import register_wallet_instruction_approve, register_wallet_instruction_approve_long, register_wallet_instruction_approve_unusual, register_wallet_instruction_reject, Instructions
import hmac
from hashlib import sha256

import pytest


def run_register_test(navigator: Navigator, client: RaggerClient, speculos_globals, wallet_policy:
                      WalletPolicy, instructions: Instructions,
                      test_name: str = "") -> None:
    wallet_policy_id, wallet_hmac = client.register_wallet(wallet_policy, navigator,
                                                           instructions=instructions,
                                                           testname=test_name,
                                                           sanity_check=False)

    assert wallet_policy_id == wallet_policy.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_policy_id, sha256).digest(),
        wallet_hmac,
    )


def test_register_blinded_wallet_accept_sh_wit(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str, speculos_globals):
    run_register_test(navigator, client, speculos_globals,
        BlindedMultisigWallet(
            name="Cold storage",
            blinding_key="slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5)",
            address_type=AddressType.SH_WIT,
            threshold=2,
            keys_info=[
                f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g",
                f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
            ],
        ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name
    )


def test_register_blinded_wallet_accept_wit(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str, speculos_globals):
    run_register_test(navigator, client, speculos_globals,
        BlindedMultisigWallet(
            name="Cold storage",
            blinding_key="slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5)",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L",
            ],
        ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name
    )


@pytest.mark.use_on_backend("speculos")
def test_register_blinded_wallet_reject_header(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str, speculos_globals):
    wallet = BlindedMultisigWallet(
        name="Bad wallet!",
        blinding_key="slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5)",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(wallet, navigator,
                               instructions=register_wallet_instruction_reject(
                                   firmware),
                               testname=test_name)

    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0


def test_register_blinded_wallet_invalid_names(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str, speculos_globals):
    too_long_name = "This wallet name is much too long since it requires 65 characters"
    assert len(too_long_name) == 65

    for invalid_name in [
        "",  # empty name not allowed
        too_long_name,  # 65 characters is too long
        " Test", "Test ",  # can't start with spaces
        "Tæst",  # characters out of allowed range
    ]:
        wallet = BlindedMultisigWallet(
            name=invalid_name,
            blinding_key="slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5)",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
        )

        with pytest.raises(ExceptionRAPDU) as e:
            client.register_wallet(wallet, navigator, testname=test_name, sanity_check=False)

        assert DeviceException.exc.get(e.value.status) == IncorrectDataError
        assert len(e.value.data) == 0


def test_register_blinded_wallet_unsupported_policy(navigator: Navigator, firmware: Firmware, client:
                                                    RaggerClient, test_name: str, speculos_globals):
    # valid policies, but not supported (might change in the future)

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(
            BlindedWallet(
                name="Unsupported",
                blinding_key="slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5)",
                descriptor_template="pk(@0/**)",  # bare pubkey, not supported
                keys_info=[
                    "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                ]
            ),
            navigator,
            testname=test_name,
            sanity_check=False
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0


def test_register_blinded_wallet_invalid_blinding_key(navigator: Navigator, firmware: Firmware, client:
                                                      RaggerClient, test_name: str, speculos_globals):
    wallet = BlindedMultisigWallet(
        name="Cold storage",
        # Invalid blinding key
        blinding_key="slip77(Xc11648c2c6df4f9dacdb4c8d35d6166d94cea2b9ad37833a82210bb7c9f5fb4)",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
        ],
    )

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(wallet, navigator, testname=test_name, sanity_check=False)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0
