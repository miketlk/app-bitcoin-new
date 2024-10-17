#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <stdio.h>    // snprintf
#include <string.h>   // memset
#include <stdint.h>

#include "os.h"
#include "ux.h"

#include "./display.h"

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.

extern bool G_was_processing_screen_shown;

static bool g_ux_flow_ended;
static bool g_ux_flow_response;
static int g_current_streaming_index;

extern dispatcher_context_t G_dispatcher_context;

ui_state_t g_ui_state;

void send_deny_sw(dispatcher_context_t *dc) {
    SEND_SW(dc, SW_DENY);
}

void set_ux_flow_response(bool approved) {
    g_ux_flow_ended = true;
    g_ux_flow_response = approved;
}

uint8_t get_streaming_index(void) {
    return g_current_streaming_index;
}

void reset_streaming_index(void) {
    PRINTF("Reset streaming index\n");
    g_current_streaming_index = 0;
}

void increase_streaming_index(void) {
    PRINTF("Increase streaming index\n");
    g_current_streaming_index += 1;
}

void decrease_streaming_index(void) {
    PRINTF("Decrease streaming index\n");
    if (g_current_streaming_index > 0) {
        g_current_streaming_index -= 1;
    }
}

// Process UI events until the current flow terminates; does not handle any APDU exchange
// This method also sets the UI state as "dirty" according to the input parameter
// so that the dispatcher refreshes resets the UI at the end of the command handler.
// Returns true/false depending if the user accepted in the corresponding UX flow.
static bool io_ui_process(dispatcher_context_t *context, bool set_dirty) {
    G_was_processing_screen_shown = false;

    g_ux_flow_ended = false;

    if (set_dirty) {
        context->set_ui_dirty();
    }

    // We are not waiting for the client's input, nor we are doing computations on the device
    io_clear_processing_timeout();

    io_seproxyhal_general_status();
    do {
        io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer), 0);
        io_seproxyhal_handle_event();
        io_seproxyhal_general_status();
    } while (io_seproxyhal_spi_is_status_sent() && !g_ux_flow_ended);

    // We're back at work, we want to show the "Processing..." screen when appropriate
    io_start_processing_timeout();

    return g_ux_flow_response;
}

bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       bool is_path_suspicious,
                       const char *pubkey) {
    ui_path_and_pubkey_state_t *state = (ui_path_and_pubkey_state_t *) &g_ui_state;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    if (!is_path_suspicious) {
        ui_display_pubkey_flow();
    } else {
        ui_display_pubkey_suspicious_flow();
    }

    return io_ui_process(context, true);
}

bool ui_display_path_and_message_content(dispatcher_context_t *context,
                                         const char *path_str,
                                         const char *message_content,
                                         uint8_t pageCount) {
    ui_path_and_message_state_t *state = (ui_path_and_message_state_t *) &g_ui_state;
    strncpy(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
    strncpy(state->message, message_content, sizeof(state->message));

    ui_sign_message_content_flow(pageCount);

    return io_ui_process(context, true);
}

bool ui_display_message_path_hash_and_confirm(dispatcher_context_t *context,
                                              const char *path_str,
                                              const char *message_hash) {
    ui_path_and_message_state_t *state = (ui_path_and_message_state_t *) &g_ui_state;
    strncpy(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
    strncpy(state->message, message_hash, sizeof(state->message));

    ui_sign_message_path_hash_and_confirm_flow();

    return io_ui_process(context, true);
}

bool ui_display_message_confirm(dispatcher_context_t *context) {
    (void) context;
    ui_sign_message_confirm_flow();

    return io_ui_process(context, true);
}

bool ui_display_register_wallet(dispatcher_context_t *context,
                                const policy_map_wallet_header_t *wallet_header,
                                const char *policy_descriptor) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->wallet_name, wallet_header->name, sizeof(state->wallet_name));
    state->wallet_name[wallet_header->name_len] = 0;
    strncpy(state->descriptor_template, policy_descriptor, sizeof(state->descriptor_template));
    state->descriptor_template[wallet_header->descriptor_template_len] = 0;

    ui_display_register_wallet_flow();

    return io_ui_process(context, true);
}

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *context,
                                           const char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           key_type_e key_type) {
    (void) (n_keys);

    ui_cosigner_pubkey_and_index_state_t *state =
        (ui_cosigner_pubkey_and_index_state_t *) &g_ui_state;

    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    if (key_type == PUBKEY_TYPE_INTERNAL) {
        snprintf(state->signer_index, sizeof(state->signer_index), "Key @%u, ours", cosigner_index);
    } else if (key_type == PUBKEY_TYPE_EXTERNAL) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u, theirs",
                 cosigner_index);
    } else if (key_type == PUBKEY_TYPE_UNSPENDABLE) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u, dummy",
                 cosigner_index);
    } else {
        LEDGER_ASSERT(false, "Unreachable code");
    }
    ui_display_policy_map_cosigner_pubkey_flow();

    return io_ui_process(context, true);
}

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->address, address, sizeof(state->address));

    if (wallet_name == NULL) {
        ui_display_default_wallet_address_flow();
    } else {
        strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
        ui_display_receive_in_wallet_flow();
    }

    return io_ui_process(context, true);
}

bool ui_authorize_wallet_spend(dispatcher_context_t *context, const char *wallet_name) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
    ui_display_spend_from_wallet_flow();

    return io_ui_process(context, true);
}

bool ui_warn_external_inputs(dispatcher_context_t *context) {
    ui_display_warning_external_inputs_flow();
    return io_ui_process(context, true);
}

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context) {
    ui_display_unverified_segwit_inputs_flows();
    return io_ui_process(context, true);
}

bool ui_warn_nondefault_sighash(dispatcher_context_t *context
                                LIQUID_PARAM(uint32_t input_index)
                                LIQUID_PARAM(uint32_t sighash_type)) {
#ifdef HAVE_LIQUID
    ui_sighash_flags_state_t *state = &g_ui_state.sighash_flags;

    LEDGER_ASSERT(input_index <= 999, "Unsupported input index");
    snprintf(state->index, sizeof(state->index), "of input #%d", input_index);
    sighash_get_name(&state->sighash_name, sighash_type);
#endif
    ui_display_nondefault_sighash_flow();
    return io_ui_process(context, true);
}

bool ui_transaction_prompt(dispatcher_context_t *context, const int external_outputs_total_count) {
    ui_display_transaction_prompt(external_outputs_total_count);
    return io_ui_process(context, true);
}

bool ui_validate_output(dispatcher_context_t *context,
                        int index,
                        int total_count,
                        const char *address_or_description,
                        const char *coin_name,
                        uint64_t amount
                        LIQUID_PARAM(uint8_t decimals)
                        LIQUID_PARAM(const uint8_t asset_tag[static 32])
                        LIQUID_PARAM(bool display_asset_tag)
                        LIQUID_PARAM(bool asset_is_reissuance_token)) {
    ui_validate_output_state_t *state = (ui_validate_output_state_t *) &g_ui_state;

    strncpy(state->address_or_description,
            address_or_description,
            sizeof(state->address_or_description));

#ifdef HAVE_LIQUID
    UNUSED(total_count);

    if (asset_is_reissuance_token) {
        format_amount("token", amount, decimals, state->amount);
        snprintf(state->token_ticker, sizeof(state->token_ticker), "of asset %s", coin_name);
    } else {
        format_amount(coin_name, amount, decimals, state->amount);
    }

    liquid_format_asset_tag(asset_tag, state->tag_hex);
    ui_display_output_address_amount_flow_ext(index, display_asset_tag, asset_is_reissuance_token);
#else
    format_sats_amount(coin_name, amount, state->amount);

    if (total_count == 1) {
        ui_display_output_address_amount_no_index_flow(index);
    } else {
        ui_display_output_address_amount_flow(index);
    }
#endif

    return io_ui_process(context, true);

}

bool ui_warn_high_fee(dispatcher_context_t *context) {
    ui_warn_high_fee_flow();

    return io_ui_process(context, true);
}

bool ui_validate_transaction(dispatcher_context_t *context,
                             const char *coin_name,
                             uint64_t fee,
                             bool is_self_transfer
                             LIQUID_PARAM(uint8_t decimals)
                             LIQUID_PARAM(const char *asset_op_type)) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

#ifdef HAVE_LIQUID
    format_amount(coin_name, fee, decimals, state->fee);
    if (asset_op_type != NULL) {
        strlcpy(state->asset_op_type, asset_op_type, sizeof(state->asset_op_type));
        ui_accept_asset_op_transaction_flow();
    } else {
        ui_accept_transaction_flow(is_self_transfer);
    }
#else
    format_sats_amount(coin_name, fee, state->fee);
    ui_accept_transaction_flow(is_self_transfer);
#endif

    return io_ui_process(context, true);
}

#ifdef HAVE_LIQUID

bool ui_warn_unknown_asset(dispatcher_context_t *context,
                           const uint8_t asset_tag[static 32]) {
    ui_asset_state_t *state = (ui_asset_state_t *) &g_ui_state;

    liquid_format_asset_tag(asset_tag, state->tag_hex);
    ui_warn_unknown_asset_flow();

    return io_ui_process(context, true);
}

bool ui_validate_asset(dispatcher_context_t *context,
                       const uint8_t asset_tag[static 32],
                       const asset_info_ext_t *asset_info) {
    ui_validate_asset_state_t *state = (ui_validate_asset_state_t *) &g_ui_state;

    liquid_format_asset_tag(asset_tag, state->tag_hex);
    strlcpy(state->ticker, asset_info->info.ticker, sizeof(state->ticker));
    strlcpy(state->name, asset_info->name, sizeof(state->name));
    strlcpy(state->domain, asset_info->domain, sizeof(state->domain));
    ui_display_validate_asset_flow();

    return io_ui_process(context, true);
}

#endif // HAVE_LIQUID

#ifdef HAVE_BAGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

void ui_pre_processing_message(void) {
    return;
}
#endif  // HAVE_BAGL

#ifdef HAVE_NBGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
    (void) context;
    ui_display_post_processing_confirm_wallet_registation(success);

    return true;
}

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success) {
    ui_display_post_processing_confirm_wallet_spend(success);

    return io_ui_process(context, success);
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
    ui_display_post_processing_confirm_transaction(success);

    return io_ui_process(context, success);
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    (void) context;
    ui_display_post_processing_confirm_message(success);

    return true;
}

void ui_pre_processing_message(void) {
    ui_set_display_prompt();
}
#endif  // HAVE_NBGL
