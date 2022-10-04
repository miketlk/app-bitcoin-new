from bitcoin_client.ledger_bitcoin import Client, AddressType, BlindedWallet, BlindedMultisigWallet
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from bitcoin_client.ledger_bitcoin.exception import DenyError

from test_utils import has_automation

import hmac
from hashlib import sha256

import pytest

@has_automation("automations/register_wallet_accept.json")
def test_register_blinded_wallet_accept_sh_wit(client: Client, speculos_globals):
    wallet = BlindedMultisigWallet(
        name="Cold storage",
        blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g/**",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**",
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )

@has_automation("automations/register_wallet_accept.json")
def test_register_blinded_wallet_accept_wit(client: Client, speculos_globals):
    wallet = BlindedMultisigWallet(
        name="Cold storage",
        blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
            "[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/**",
            "[9860e1eb/48'/1'/0'/2']tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/**"
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )

@has_automation("automations/register_wallet_reject.json")
def test_register_blinded_wallet_reject_header(client: Client):
    wallet = BlindedMultisigWallet(
        name="Reject me!",
        blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
    )

    with pytest.raises(DenyError):
        client.register_wallet(wallet)

@has_automation("automations/register_wallet_accept.json")
def test_register_blinded_wallet_invalid_names(client: Client):
    for invalid_name in [
        "",  # empty name not allowed
        "Very long walletz",  # 17 characters is too long
        " Test", "Test ",  # can't start with spaces
        "Tæst",  # characters out of allowed range
    ]:
        wallet = BlindedMultisigWallet(
            name=invalid_name,
            blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
                f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
            ],
        )

    with pytest.raises(IncorrectDataError):
        client.register_wallet(wallet)


@has_automation("automations/register_wallet_accept.json")
def test_register_blinded_wallet_unsupported_policy(client: Client):
    # valid policise, but not supported (might change in the future)

    with pytest.raises(NotSupportedError):
        client.register_wallet(BlindedWallet(
            name="Unsupported",
            blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
            policy_map="sh(pkh(@0))",  # unusual script, not in the whitelist
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            ]
        ))

    with pytest.raises(NotSupportedError):
        # Not supporting keys without wildcard
        client.register_wallet(BlindedMultisigWallet(
            name="Cold storage",
            blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
        ))

    with pytest.raises(NotSupportedError):
        # Not supporting keys without origin information (even if external)
        client.register_wallet(BlindedMultisigWallet(
            name="Cold storage",
            blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                f"tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
                f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
            ],
        ))

@has_automation("automations/register_wallet_accept.json")
def test_register_blinded_wallet_invalid_blinding_key(client: Client, speculos_globals):
    wallet = BlindedMultisigWallet(
        name="Cold storage",
        # valid blinding key should be L1XvKmn...
        blinding_key="L2XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g/**",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**",
        ],
    )

    with pytest.raises(IncorrectDataError):
        client.register_wallet(wallet)