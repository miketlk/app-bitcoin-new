#ifdef HAVE_LIQUID

#include <stdint.h>
#include <string.h>

#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../commands.h"
#include "../crypto.h"
#include "../liquid/liquid.h"

void handler_liquid_get_master_blinding_key(dispatcher_context_t *dc, uint8_t protocol_version) {
    UNUSED(protocol_version);

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t mbk[32];

    if (!liquid_get_master_blinding_key(mbk)) {
        // Unexpected error
        SEND_SW(dc, SW_BAD_STATE);
    } else {
        SEND_RESPONSE(dc, mbk, sizeof(mbk), SW_OK);
    }
    explicit_bzero(mbk, sizeof(mbk));
}

#endif // HAVE_LIQUID