/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2024 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#ifdef HAVE_CCMD_PRINTF
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "printf.h"
#endif

#include "dispatcher.h"
#include "constants.h"
#include "globals.h"
#include "io.h"
#include "sw.h"

#include "common/buffer.h"

extern dispatcher_context_t G_dispatcher_context;

extern bool G_was_processing_screen_shown;

// Private state that is not made accessible from the dispatcher context
struct {
    void (*termination_cb)(void);
    uint16_t sw;
    bool had_ux_flow;  // set to true if there was any UX flow during the APDU processing
} G_dispatcher_state;

static void add_to_response(const void *rdata, size_t rdata_len) {
    io_add_to_response(rdata, rdata_len);
}

static void finalize_response(uint16_t sw) {
    G_dispatcher_state.sw = sw;
    io_finalize_response(sw);
}

static void send_response() {
    io_confirm_response();
}

static void set_ui_dirty() {
    // signals that the screen was changed while processing a command handler
    G_dispatcher_state.had_ux_flow = true;
}

// TODO: refactor code in common with the main apdu loop
static int process_interruption(dispatcher_context_t *dc) {
    command_t cmd;
    // We declare `input_len` as volatile to keep static analysis tools calm while allowing
    // io_exchange() to return error codes as negative values in future versions of the SDK.
    volatile int input_len;

    // Reset structured APDU command
    memset(&cmd, 0, sizeof(cmd));

    io_start_interruption_timeout();

    // Receive command bytes in G_io_apdu_buffer
    if (input_len = io_exchange(CHANNEL_APDU, G_output_len) < 0) {
        return -1;
    }

    io_clear_interruption_timeout();

    G_output_len = 0;

    // As we are not yet returning anything here, we communicate to io_exchange that the apdu
    // is consumed. Otherwise the io_exchange call in main.c might receive an unexpected duplicate
    // APDU that was already processed (this would happen if this is the latest interruption in the
    // caller processor, for example if the dispatcher is paused because of a UX interaction).
    G_io_app.apdu_length = 0;

    G_dispatcher_state.sw = 0;

    // Parse APDU command from G_io_apdu_buffer
    if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return -1;
    }

    LOG_APDU(&cmd);

    // INS_CONTINUE is the only valid apdu here
    if (cmd.cla != CLA_FRAMEWORK || cmd.ins != INS_CONTINUE) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return -1;
    }

    dc->read_buffer = buffer_create(cmd.data, cmd.lc);

    return 0;
}

void apdu_dispatcher(command_descriptor_t const cmd_descriptors[],
                     int n_descriptors,
                     void (*termination_cb)(void),
                     const command_t *cmd) {
    G_dispatcher_state.had_ux_flow = false;

    G_dispatcher_state.termination_cb = termination_cb;
    G_dispatcher_state.sw = 0;

    G_dispatcher_context.add_to_response = add_to_response;
    G_dispatcher_context.finalize_response = finalize_response;
    G_dispatcher_context.send_response = send_response;
    G_dispatcher_context.set_ui_dirty = set_ui_dirty;
    G_dispatcher_context.process_interruption = process_interruption;

    G_dispatcher_context.read_buffer = buffer_create(cmd->data, cmd->lc);

    if (cmd->p2 > CURRENT_PROTOCOL_VERSION) {
        io_send_sw(SW_WRONG_P1P2);
        return;
    }

    if (cmd->cla == CLA_FRAMEWORK && cmd->ins == INS_CONTINUE) {
        PRINTF("Unexpected INS_CONTINUE.\n");
        io_send_sw(SW_BAD_STATE);  // received INS_CONTINUE, but no command was interrupted.
        return;
    } else {
        bool cla_found = false, ins_found = false;
        command_handler_t handler;
        for (int i = 0; i < n_descriptors; i++) {
            if (cmd_descriptors[i].cla != cmd->cla) continue;
            cla_found = true;
            if (cmd_descriptors[i].ins != cmd->ins) continue;
            ins_found = true;

            handler = (command_handler_t) PIC(cmd_descriptors[i].handler);
            break;
        }

        if (!cla_found) {
            io_send_sw(SW_CLA_NOT_SUPPORTED);
            PRINTF("Instrunction class not supported CLA=0x%02X INS=0x%02X\n", cmd->cla, cmd->ins);
            return;
        } else if (!ins_found) {
            PRINTF("Instrunction not supported CLA=0x%02X INS=0x%02X\n", cmd->cla, cmd->ins);
            io_send_sw(SW_INS_NOT_SUPPORTED);
            return;
        }

        io_start_processing_timeout();
        handler(&G_dispatcher_context, cmd->p2);
    }

    // Here a response (either success or error) should have been send.
    // Failure to do so indicates a bug in the last command processors.
    if (G_dispatcher_state.sw == 0) {
        PRINTF("No response before terminating\n");
        io_send_sw(SW_BAD_STATE);
    }

    // We call the termination callback if given, but only if the UX is "dirty", that is either
    // - there was some kind of UX flow with user interaction;
    // - background processing took long enough that the "Processing..." screen was shown.
    bool is_ux_dirty = G_dispatcher_state.had_ux_flow || G_was_processing_screen_shown;
    if (G_dispatcher_state.termination_cb != NULL && is_ux_dirty) {
        G_dispatcher_state.termination_cb();
        G_was_processing_screen_shown = 0;
    }

    io_clear_processing_timeout();
}

#ifdef HAVE_LOG_PROCESSOR
// Print current filename, line number and function name.
// Indents according to the nesting depth for subprocessors.
void print_dispatcher_info(const char *file, int line, const char *func) {
    // PRINTF() replaced with low-level functions to reduce stack usage (~ 40 vs 500 bytes)

    debug_write("->");
    debug_write(file);
    debug_write(":");
    debug_write_dec(line);
    debug_write(": ");
    debug_write(func);
#ifdef HAVE_BOLOS_APP_STACK_CANARY
    if (app_stack_canary != STACK_CANARY_CONSTANT) {
        debug_write(" STACK CORRUPTED!");
    } else {
        debug_write(" stack avl ");
        debug_write_dec(stack_available_bytes());
        debug_write(" min ");
        debug_write_dec(stack_unused_bytes());
    }
#endif
    debug_write("\n");
}
#endif

#ifdef HAVE_CCMD_PRINTF

#define CCMD_DEBUG 0xEE

int ccmd_printf(dispatcher_context_t *dc, const char *format, ...) {
    char buf[1 + 128 + 1];

    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf + 1, sizeof(buf) - 2, format, args);
    va_end(args);

    if (ret > 0) {
        buf[0] = CCMD_DEBUG;
        buf[1 + ret] = '\0';
        dc->add_to_response(buf, 1 + ret);
        dc->finalize_response(SW_INTERRUPTED_EXECUTION);
        return dc->process_interruption(dc);
    }

    return 0;
}
#endif  // HAVE_CCMD_PRINTF

#ifdef HAVE_APDU_LOG
void log_apdu(const command_t *cmd) {
    debug_write("=> CLA=");
    debug_write_hex(cmd->cla, 1);
    debug_write(" | INS=");
    debug_write_hex(cmd->ins, 1);
    debug_write(" | P1=");
    debug_write_hex(cmd->p1, 1);
    debug_write(" | P2=");
    debug_write_hex(cmd->p2, 1);
    debug_write(" | Lc=");
    debug_write_hex(cmd->lc, 1);
    debug_write(" | CData=");

    for (int i = 0; i < cmd->lc; i++) {
        debug_write_hex(cmd->data[i], 1);
    }
    debug_write("\n");
}
#endif