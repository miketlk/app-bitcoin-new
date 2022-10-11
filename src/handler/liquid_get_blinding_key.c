/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
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

#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../commands.h"
#include "../crypto.h"
#include "../liquid/liquid.h"

#include "liquid_get_blinding_key.h"

void handler_liquid_get_blinding_key(dispatcher_context_t *dc) {
    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint64_t script_length;
    if (!buffer_read_varint(&dc->read_buffer, &script_length)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (!buffer_can_read(&dc->read_buffer, (size_t)script_length)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    if (script_length > GET_BLINDING_KEY_MAX_SCRIPT_LEN) {
        PRINTF("Script too long\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint8_t mbk[32];
    uint8_t blinding_key[32];
    
    bool ok =  liquid_get_master_blinding_key(mbk);
    uint8_t *script_ptr = dc->read_buffer.ptr + dc->read_buffer.offset;
    ok = ok && liquid_get_blinding_key(mbk, script_ptr, script_length, blinding_key);

    explicit_bzero(mbk, sizeof(mbk));

    if (!ok) {
        // Unexpected error
        explicit_bzero(blinding_key, sizeof(blinding_key));
        SEND_SW(dc, SW_BAD_STATE);
    } else {
        SEND_RESPONSE(dc, blinding_key, sizeof(blinding_key), SW_OK);
    }
}
