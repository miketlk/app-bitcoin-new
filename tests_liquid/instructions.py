from ragger.navigator import NavInsID
from ragger.firmware import Firmware

from ragger_bitcoin.ragger_instructions import Instructions


def message_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path")
        instructions.same_request("Sign")
    else:
        instructions.confirm_message()
    return instructions


def message_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path")
        instructions.same_request("Processing")
        instructions.new_request("Processing")
        instructions.new_request("Processing")
        instructions.new_request("Processing")
        instructions.new_request("Sign")
    else:
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.confirm_message()
    return instructions


def message_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject")
    else:
        instructions.reject_message()

    return instructions


def pubkey_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
    else:
        instructions.choice_confirm()
    return instructions


def pubkey_instruction_reject_early(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject")
    else:
        instructions.footer_cancel()
    return instructions


def pubkey_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Reject")
        instructions.same_request("Reject")
    else:
        instructions.choice_reject()

    return instructions


def register_wallet_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.new_request("Approve")
        instructions.new_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.new_request("Approve")
        instructions.new_request("Approve")
        instructions.new_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_approve_unusual(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.new_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject")
    else:
        instructions.choice_reject()

    return instructions


def liquid_sign_psbt_instruction_approve(model: Firmware,
                                         wallet_spend: bool = False,
                                         nondef_sighash: int = 0,
                                         unknown_assets: int = 0,
                                         assets: int = 0,
                                         outs: int = 1,
                                         save_screenshots: bool = True) -> Instructions:
    """Generates instructions for signing a PSET

    :param model: The Firmware that defines the wallet model
    :type model: Firmware
    :param wallet_spend: whether a nonstandard wallet is being spent, defaults to False
    :type wallet_spend: bool, optional
    :param nondef_sighash: number of inputs with non-default sighashes, defaults to 0
    :type nondef_sighash: int, optional
    :param unknown_assets: number of assets with no metadata, defaults to 0
    :type unknown_assets: int, optional
    :param assets: number of assets with included metadata, defaults to 0
    :type assets: int, optional
    :param outs: number of transaction outputs to confirm, defaults to 1
    :type outs: int, optional
    :param save_screenshots: request screenshot comparison, defaults to True
    :type save_screenshots: bool, optional
    :raises NotImplementedError: for unsupported wallet models
    :return: automation instructions
    :rtype: Instructions
    """

    instructions = Instructions(model)

    if model.name.startswith("nano"):
        if wallet_spend:
            # Spend from|known wallet > Wallet name: > Continue <>
            instructions.new_request("Continue", save_screenshot=save_screenshots)
        for _ in range(0, nondef_sighash):
            # Non-default sighash > Reject if you're|not sure > Continue <>
            instructions.new_request("Continue", save_screenshot=save_screenshots)
        for _ in range(0, unknown_assets):
            # The asset|is unknown > Asset tag(1..4/4) > Reject if you're|not sure > Continue <>
            instructions.new_request("Continue", save_screenshot=save_screenshots)
        for _ in range(0, assets):
            # Confirm asset > Asset tag (1..4/4) > Asset name > Asset domain > Approve <>
            instructions.new_request("Approve", save_screenshot=save_screenshots)
        for _ in range(0, outs):
            # Review|output #x > Amount > Asset tag(1..4/4) > Address(1..3/3) > Continue <>
            instructions.new_request("Continue", save_screenshot=save_screenshots)

        # Fees > Sign|transactoion <>
        instructions.new_request("Sign", save_screenshot=save_screenshots)
    else:
        # TODO: implement for Stax/Flex
        raise NotImplementedError("Unsupported wallet model")
    return instructions