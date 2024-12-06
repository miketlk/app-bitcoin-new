#pragma once

#include "os.h"

// Workaround
#ifdef HAVE_SEMIHOSTED_PRINTF
    #ifdef PRINTF
        #undef PRINTF
    #endif
    #define PRINTF semihosted_printf
#endif // HAVE_SEMIHOSTED_PRINTF

void debug_write(const char *buf);
void debug_write_hex(unsigned int word, unsigned int bytes);
void debug_write_dec(unsigned int word);

int semihosted_printf(const char *format, ...);

void print_stack_pointer(const char *file, int line, const char *func_name);
void print_hash(const char *msg, const void *sha256_context);
void print_data_hash(const char *msg, const void *buf, unsigned int len);
void print_hex(const char *msg, const void *buf, unsigned int len);
void print_hex_reverse(const char *msg, const void *buf, unsigned int len);
void print_uint(const char *msg, unsigned int word);
void print_strn(const char *msg, const char *str, int len);

// Helper macro
#ifdef HAVE_PRINT_STACK_POINTER
#define PRINT_STACK_POINTER() print_stack_pointer(__FILE__, __LINE__, __func__)
#else
#define PRINT_STACK_POINTER()
#endif

#ifdef HAVE_PRINTF
#define PRINT_HASH(msg, sha256_context) print_hash(msg, sha256_context)
#define PRINT_DATA_HASH(msg, buf, len) print_data_hash(msg, buf, len)
#define PRINT_HEX(msg, buf, len) print_hex(msg, buf, len)
#define PRINT_HEX_REV(msg, buf, len) print_hex_reverse(msg, buf, len)
#define PRINT_UINT(msg, word) print_uint(msg, word)
#define PRINT_STR(msg, str) print_strn(msg, str, -1)
#define PRINT_STRN(msg, str, len) print_strn(msg, str, len)
#else
#define PRINT_HASH(msg, sha256_context)
#define PRINT_DATA_HASH(msg, buf, len)
#define PRINT_HEX(msg, buf, len)
#define PRINT_HEX_REV(msg, buf, len)
#define PRINT_UINT(msg, word)
#define PRINT_STR(msg, str)
#define PRINT_STRN(msg, str, len)
#endif // HAVE_PRINTF


static inline int print_error_info(const char *error_msg,
                                   const char *filename,
                                   int line,
                                   int retval) {
    (void) error_msg;
    (void) filename;
    (void) line;

    PRINTF("ERR (%s::%d): %s\n", filename, line, error_msg);
    return retval;
}

#define WITH_ERROR(retval, error_msg) print_error_info(error_msg, __FILE__, __LINE__, retval)