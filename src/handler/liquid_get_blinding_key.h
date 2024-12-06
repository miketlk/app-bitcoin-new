#pragma once
#ifdef HAVE_LIQUID

#include "../boilerplate/dispatcher.h"

/// State of LIQUID_GET_BLINDING_KEY handler
typedef struct {
    /// Machine context for command dispatcher
    machine_context_t ctx;
} liquid_get_blinding_key_t;

/**
 * Handles LIQUID_GET_BLINDING_KEY command.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context.
 */
void handler_liquid_get_blinding_key(dispatcher_context_t *dispatcher_context);

#endif // HAVE_LIQUID