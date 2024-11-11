#include <stdio.h>
#include <stdarg.h>
#include "printf.h"
#include "cx.h"
#include "crypto.h"
#include "globals.h"

#pragma GCC diagnostic ignored "-Wunused-function"

static const char dectohex[16] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void debug_write(const char *buf) {
    asm volatile(
        "movs r0, #0x04\n"
        "movs r1, %0\n"
        "svc      0xab\n" ::"r"(buf)
        : "r0", "r1");
}

void debug_write_hex(unsigned int word, unsigned int bytes) {
    if (bytes && bytes <= 4) {
        char asc[9];
        char *p_asc = asc;

        word <<= (4 - bytes) << 3;
        for (unsigned int i = 0; i < bytes; ++i) {
            *p_asc++ = dectohex[word >> 28 & 15];
            *p_asc++ = dectohex[word >> 24 & 15];
            word <<= 8;
        }
        *p_asc = '\0';
        debug_write(asc);
    }
}

void debug_write_dec(unsigned int word) {
    if (word == 0) {
        debug_write("0");
    } else {
        char asc[11];
        unsigned int i;
        for (i = 9; i >= 0; --i) {
            asc[i] = '0' + word % 10;
            if (word == 0) {
                break;
            }
            word /= 10;
        }
        asc[10] = '\0';
        debug_write(asc + i + 1);
    }
}

int semihosted_printf(const char *format, ...) {
    char buf[128 + 1];

    va_list args;
    va_start(args, format);

    int ret = vsnprintf(buf, sizeof(buf) - 1, format, args);

    va_end(args);

    if (ret > 0) {
        buf[ret] = 0;
        debug_write(buf);
    }

    return ret;
}

// Returns the current stack pointer
static unsigned int __attribute__((noinline)) get_stack_pointer() {
    unsigned int stack_top = 0;

    __asm__ __volatile__("mov %0, sp" : "=r"(stack_top) : :);

    return stack_top;
}

#ifdef HAVE_BOLOS_APP_STACK_CANARY

void stack_fill_canary(void) {
    unsigned int *ptr = (unsigned int *) (get_stack_pointer() - 4 * sizeof(void *));
    // Handle canary variable separately because it can be located at NULL address
    app_stack_canary = STACK_CANARY_CONSTANT;
    while (ptr > &app_stack_canary) {
        *ptr-- = STACK_CANARY_CONSTANT;
    }
}

unsigned int stack_unused_bytes(void) {
    unsigned int *ptr = &app_stack_canary;
    unsigned int *ptr_end = (unsigned int *) (get_stack_pointer());
    unsigned int n_words = 0;

    while (ptr < ptr_end) {
        if (*ptr++ != STACK_CANARY_CONSTANT) {
            break;
        }
        ++n_words;
    }
    return n_words * sizeof(unsigned int);
}

unsigned int stack_available_bytes(void) {
    unsigned int t = get_stack_pointer();
    return t >= ((unsigned int) &app_stack_canary) ? t - ((unsigned int) &app_stack_canary) : 0;
}

#endif  // HAVE_BOLOS_APP_STACK_CANARY

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"
void print_stack_pointer(const char *file, int line, const char *func_name) {
    (void) file, (void) line, (void) func_name;  // avoid warnings when DEBUG == 0

    // PRINTF() replaced with low-level functions to reduce stack usage (~ 40 vs 500 bytes)

    debug_write("STACK (");
    debug_write(func_name);
    debug_write(") ");
    debug_write(file);
    debug_write(":");
    debug_write_dec(line);
    debug_write(": ");
    debug_write_hex(get_stack_pointer(), 4);
#ifdef HAVE_BOLOS_APP_STACK_CANARY
    if (app_stack_canary != STACK_CANARY_CONSTANT) {
        debug_write(" CORRUPTED!");
    } else {
        debug_write(" avl ");
        debug_write_dec(stack_available_bytes());
        debug_write(" min ");
        debug_write_dec(stack_unused_bytes());
    }
#endif
    debug_write("\n");
}
#pragma GCC diagnostic pop

void print_hash(const char *msg, const void *sha256_context) {
    if (sha256_context) {
        cx_sha256_t ctx = *(const cx_sha256_t *) sha256_context;
        uint8_t hash[32] = {0};
        crypto_hash_digest(&ctx.header, hash, 32);
        cx_hash_sha256(hash, 32, hash, 32);

        debug_write("HASH '");
        debug_write(msg);
        debug_write("' ");
        for (int i = 0; i < 32; ++i) {
            debug_write_hex(hash[i], 1);
        }
        debug_write("\n");
    }
}

void print_data_hash(const char *msg, const void *buf, unsigned int len) {
    uint8_t hash[32] = {0};
    cx_hash_sha256(buf, len, hash, 32);

    debug_write("HASH '");
    debug_write(msg);
    debug_write("' ");
    for (unsigned int i = 0; i < 32; ++i) {
        debug_write_hex(hash[i], 1);
    }
    debug_write("\n");
}

void print_hex(const char *msg, const void *buf, unsigned int len) {
    const uint8_t *bytes = (const uint8_t *) buf;
    debug_write(msg);
    for (unsigned int i = 0; i < len; ++i) {
        debug_write_hex(bytes[i], 1);
    }
    debug_write("\n");
}

void print_hex_reverse(const char *msg, const void *buf, unsigned int len) {
    const uint8_t *bytes = (const uint8_t *) buf;
    debug_write(msg);
    for (int i = (int) (len - 1); i >= 0; --i) {
        debug_write_hex(bytes[i], 1);
    }
    debug_write("\n");
}

void print_uint(const char *msg, unsigned int word) {
    debug_write(msg);
    debug_write_dec(word);
    debug_write("\n");
}

void print_strn(const char *msg, const char *str, int len) {
    char buf[4];
    int idx = 0;
    buf[sizeof(buf) - 1] = '\0';

    debug_write(msg);

    while ((len < 0 || len--) && *str) {
        buf[idx++] = *str++;
        if (idx == sizeof(buf) - 1) {
            debug_write(buf);
            idx = 0;
        }
    }
    if (idx) {
        buf[idx] = '\0';
        debug_write(buf);
    }
    debug_write("\n");
}
