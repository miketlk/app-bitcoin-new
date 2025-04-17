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
    assert res == "tex1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6njktcw"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "tex1qlrvzyx8jcjfj2xuy69du9trtxnsvjupehhdgda"


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
    assert res == "tlq1qqvk6gl0lgs80w8rargdqyfsl7f0llsttzsx8gd4fz262cjnt0uxh6y68aq4qx76ahvuvlrz8t8ey9v04clsf5utzxs3jk5msz"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "tlq1qqwfu5kl52jxc05g5nrux3almgt4ryz8eandhsjjnjw3k0jhetd9vp7xcygv093yny5dcf52mc2kxkd8qe9crjdkvj29as45eh"


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
    assert res == "8kTzKh7vfskVq8bD2b2RHdya2twLWCmR8i"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "8wman2geWUEz3QQRGGyciBV5aY1pMJbART"


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
    assert res == "vjU7NNQpSPxe2GLKhtB6phQ35bwxP7dQE7ESi4YoVD5px8do6FQiKiEnFkTe1uBodCBC3BLAqfnFZaNz"

    res = client.get_wallet_address(wallet, None, 1, 15, False, sanity_check=False)
    assert res == "vjU7jVGmGg7RQCcGj7wC3u1FPYSGMcKL6d11qQ18Vxmk4vmmdDBda1j95DSHBfEYDVQdD82cKPd5qbsF"

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
    assert res == "91RmpYdgGgamwpee8kn77LEFbzP6QBf3ZZ"


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
    assert res == "vjTzSV9ksKEhdzuUwG5RBAL8Cj2hSRV7Jq7fy7H2yoHaTBjiqnroqmWwdZLJY7yEHPQ39GA1KSnr3Mxh"


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
    assert res == "tex1qm00c95pvkjp97fvswsl09j7pgt75m54srzsu2y87wau7v423q2kqarlrs9"


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
    assert res == "tlq1qqwuytsp6xrqhuku4cqqftdasvf6d6rkxjlrf90ptm3670tx2pkwlfk7lstgzedyztujeqap77t9uzshafhftqx9pc5g0uameue24zq4vkcxh9ar9hkdl"


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
