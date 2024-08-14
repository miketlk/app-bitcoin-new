from ledger_bitcoin import Client, AddressType, MultisigWallet, WalletPolicy, BlindedWallet, BlindedMultisigWallet
from ledger_bitcoin.exception.errors import IncorrectDataError
from ledger_bitcoin.exception.device_exception import DeviceException
from ragger.error import ExceptionRAPDU
from ragger_bitcoin import RaggerClient

import pytest


def test_get_wallet_address_singlesig_wit(client: RaggerClient):
    # bech32 address (P2WPKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="wpkh(@0/**)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False, sanity_check=False)
    assert res == "ert1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6nxw6ml"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "ert1qlrvzyx8jcjfj2xuy69du9trtxnsvjupehr4ewv"


def test_get_wallet_confidential_address_singlesig_wit(client: RaggerClient):
    # bech32 address (P2WPKH)
    wallet = BlindedWallet(
        name="",
        blinding_key="slip77(0c11648c2c6df4f9dacdb4c8d35d6166d94cea2b9ad37833a82210bb7c9f5fb4)",
        descriptor_template="wpkh(@0/**)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False, sanity_check=False)
    assert res == "el1qqvk6gl0lgs80w8rargdqyfsl7f0llsttzsx8gd4fz262cjnt0uxh6y68aq4qx76ahvuvlrz8t8ey9v04clsf58w045gzmxga3"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "el1qqwfu5kl52jxc05g5nrux3almgt4ryz8eandhsjjnjw3k0jhetd9vp7xcygv093yny5dcf52mc2kxkd8qe9crjknppwuda885y"


def test_get_wallet_address_singlesig_sh_wit(client: RaggerClient):
    # wrapped segwit addresses (P2SH-P2WPKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="sh(wpkh(@0/**))",
        keys_info=[
            f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False, sanity_check=False)
    assert res == "XHPmTmp4RyhZdQQ4Q5gGSfDdH9NAJf8LFn"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "XUhMv7NnGaC3qgDGdmdTsCj8pnSeDSccur"


def test_get_wallet_confidential_address_singlesig_sh_wit(client: RaggerClient):
    # wrapped segwit addresses (P2SH-P2WPKH)
    wallet = BlindedWallet(
        name="",
        blinding_key="slip77(0c11648c2c6df4f9dacdb4c8d35d6166d94cea2b9ad37833a82210bb7c9f5fb4)",
        descriptor_template="sh(wpkh(@0/**))",
        keys_info=[
            f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False, sanity_check=False)
    assert res == "AzpwWmd4zRxfbpKrQRyTrbz5uzaPtvkYqMo5TTzEwk84fsR8mmymQZcCw2Y8nFh7duqWAp9n8fHaeaQJ"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "AzpwstV1pi7SykboRfjZ5obJDw4hsRSUhsZeaoSZxVoynfZ7Jjkges6ZkVWmx1jrED4wLkrDcP8M4Zzk"


def test_get_wallet_address_singlesig_taproot(client: RaggerClient):
    # test for a native taproot wallet (bech32m addresses, per BIP-0086)

    wallet = WalletPolicy(
        name="",
        descriptor_template="tr(@0/**)",
        keys_info=[
            f"[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0, 0, False, sanity_check=False)
    assert res == "ert1pvqrp5jpwxsg7uh808md6ax28a9u97w7vss3w22zuakkncgup3haqyp0p9v"

    res = client.get_wallet_address(wallet, None, 0, 9, False, sanity_check=False)
    assert res == "ert1pvhmw0tzfyaj8r83plwlmh277vdxflnfszhsqhd4rq9jsy89229ksla9znj"

    res = client.get_wallet_address(wallet, None, 1, 0, False, sanity_check=False)
    assert res == "ert1p26d4l6tj94kncqjtc30uyxcq7202a7496h0j9ev5kq96w5dpgpss2nmh5n"

    res = client.get_wallet_address(wallet, None, 1, 9, False, sanity_check=False)
    assert res == "ert1pdnk6rl49gdwt2twvkrmqsv4d9k62fc6crte2cm9qc94fnnwexxhqfksrk7"


def test_get_wallet_confidential_address_singlesig_taproot(client: RaggerClient):
    # test for a native taproot wallet (bech32m addresses, per BIP-0086)

    wallet = BlindedWallet(
        name="",
        blinding_key="slip77(0c11648c2c6df4f9dacdb4c8d35d6166d94cea2b9ad37833a82210bb7c9f5fb4)",
        descriptor_template="tr(@0/**)",
        keys_info=[
            f"[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0, 0, False, sanity_check=False)
    assert res == "el1pqdpcdl0hc7hm06nm8hu62twyyg4uktspl69vswqkjqmzl52ncm67ccqxrfyzudq3aeww70km46v506tctuaueppzu559emdd8s3crr06tc6f043v5jk2"

    res = client.get_wallet_address(wallet, None, 0, 9, False, sanity_check=False)
    assert res == "el1pqdj37x80k0d8wh945s7s894x3f65g9lzantnchpqp02w6j9e5qwfje0ku7kyjfmywx0zr7alhw4auc6vnlxnq90qpwm2xqt9qgw255td0mxzvya8hhvs"

    res = client.get_wallet_address(wallet, None, 1, 0, False, sanity_check=False)
    assert res == "el1pqwuvnksvmpncppf8n9cm4panrlkece8rr074mehrwt085dazeuqzu45mtl5hyttd8spyh3zlcgdspu574ma2t4wlytjefvqt5ag6zsrphzvg58g2r8jm"

    res = client.get_wallet_address(wallet, None, 1, 9, False, sanity_check=False)
    assert res == "el1pqd8hp70l67ulukcesx7dtsv3u2c3uqhzsmaylf2ltqjvlh8k7jagjm8d58l22s6uk5kuev8kpqe26td55n34sxhj43k2pst2n8xajvdw6cngcs5hm26h"

# Multisig

def test_get_wallet_address_multisig_sh_wit(client: Client, speculos_globals):
    # test for a wrapped segwit multisig wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
            f"[42b01983/48'/1'/0'/1']tpubDFjEjEPeyFun4mXBDxjLLx7hSM8jpMYNoSckRMtYygsAh4ZUtXKJtczddeHRKQ1Mzq8B6MWy3iUJyeKmJwiEKDd4rXxazBSjAEHzibDEhVK"
        ],
    )

    res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0, 0, False, sanity_check=False)
    assert res == "XYMYxdKp2nXqk6TVWFRxGMUJrEovELhDvc"


def test_get_wallet_confidential_address_multisig_sh_wit(client: Client, speculos_globals):
    # test for a blinded wrapped segwit multisig wallet

    # ct(slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5),sh(wsh(sortedmulti(2,
    #   [f5acc2fd/48h/1h/0h/2h]tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/{0,1}/*,
    #   [42b01983/48h/1h/0h/2h]tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/{0,1}/*,
    #   [9860e1eb/48h/1h/0h/2h]tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/{0,1}/*
    # ))))

    wallet = BlindedMultisigWallet(
        name="Cold storage",
        blinding_key="slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5)",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            f"[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L",
            f"[9860e1eb/48'/1'/0'/2']tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy"
        ],
    )

    res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0, 0, False, sanity_check=False)
    assert res == "AzppatN1RMEjDYu1dosnD4vB37f8xEcFv5gJiWiUSLKpAvX4XKRrvctNJqQoJUUYJ74MGtyccSNcvJPS"


def test_get_wallet_address_multisig_wit(client: Client, speculos_globals):
    # test for a native segwit multisig wallet (bech32 address)

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            "[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L",
            "[9860e1eb/48'/1'/0'/2']tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy"
        ],
    )

    res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0, 0, False, sanity_check=False)
    assert res == "ert1qm00c95pvkjp97fvswsl09j7pgt75m54srzsu2y87wau7v423q2kqthjx8a"


def test_get_wallet_confidential_address_multisig_wit(client: Client, speculos_globals):
    # test for a native segwit multisig wallet (bech32 address)

    # ct(slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5),wsh(sortedmulti(2,
    #   [f5acc2fd/48h/1h/0h/2h]tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/{0,1}/*,
    #   [42b01983/48h/1h/0h/2h]tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/{0,1}/*,
    #   [9860e1eb/48h/1h/0h/2h]tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/{0,1}/*
    # )))

    wallet = BlindedMultisigWallet(
        name="Cold storage",
        blinding_key="slip77(80b796c76c895bda151cd5c40f3a11afcd96d66f99347a760d3f7b8aaa5815b5)",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            "[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L",
            "[9860e1eb/48'/1'/0'/2']tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy"
        ],
    )

    res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0, 0, False, sanity_check=False)
    assert res == "el1qqwuytsp6xrqhuku4cqqftdasvf6d6rkxjlrf90ptm3670tx2pkwlfk7lstgzedyztujeqap77t9uzshafhftqx9pc5g0uameue24zq4vcu0n02rjs05c"


# Failure cases for default wallets

def test_get_wallet_address_default_fail_wrongkeys(client: RaggerClient):
    # 0 keys info should be rejected
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="wpkh(@0/**)",
            keys_info=[],
        ), None, 0,  0, False, sanity_check=False)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0

    # more than 1 key should be rejected
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="wpkh(@0/**)",
            keys_info=[
                f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
                f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
            ],
        ), None, 0,  0, False, sanity_check=False)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0

    # wrong BIP44 purpose should be rejected (here using 49' for a P2WPKH address)
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="wpkh(@0/**)",
            keys_info=[
                f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3",
            ],
        ), None, 0,  0, False, sanity_check=False)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0

    # mismatching pubkey (claiming key origin "84'/1'/0'", but that's the extended dpubkey for "49'/1'/0'"")
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="wpkh(@0/**)",
            keys_info=[
                f"[f5acc2fd/84'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3",
            ],
        ), None, 0,  0, False, sanity_check=False)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0

    # wrong master fingerprint
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="wpkh(@0/**)",
            keys_info=[
                f"[05acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
            ],
        ), None, 0,  0, False, sanity_check=False)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0

    # too large address_index, cannot be done non-silently
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="wpkh(@0/**)",
            keys_info=[
                f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
            ],
        ), None, 0,  100000, False, sanity_check=False)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0
