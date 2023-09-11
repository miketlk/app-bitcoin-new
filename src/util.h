#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/**
 * Fall-through between switch labels as Clang C attribute
 */
#if defined (__has_c_attribute)
#if __has_c_attribute(fallthrough)
#define UTIL_FALLTHROUGH [[fallthrough]]
#endif

/**
 * Fall-through between switch labels as Clang C++ attribute
 */
#elif defined(__cplusplus) && defined(__has_cpp_attribute)
#if __has_cpp_attribute(fallthrough)
#define UTIL_FALLTHROUGH [[fallthrough]]
#endif
#endif

/**
 * Fall-through between switch labels as GCC attribute
 */
#ifndef UTIL_FALLTHROUGH
#if defined(__GNUC__) && __GNUC__ >= 4
#define UTIL_FALLTHROUGH __attribute__ ((fallthrough))
#else
#define UTIL_FALLTHROUGH
#endif
#endif

/**
 * Reverses data in-place.
 *
 * @param[in,out] buf
 *   Buffer which contents needs to be reversed.
 * @param[in] len
 *   Length of the buffer in bytes.
 */
static inline void reverse_inplace(uint8_t *buf, size_t len) {
    uint8_t *p_end = buf + len - 1;
    for (size_t i = 0; i < len >> 1; ++i) {
        uint8_t tmp = *buf;
        *buf++ = *p_end;
        *p_end-- = tmp;
    }
}

/**
 * Copies bytes from one buffer to another in reverse order.
 *
 * @param[out] dst
 *   Destination buffer.
 * @param[in] src
 *   Source buffer.
 * @param len
 *   Number of bytes to copy.
 */
static inline void reverse_copy(uint8_t *dst, const uint8_t *src, size_t len) {
    const uint8_t *p_src = src + len - 1;
    for (size_t i = 0; i < len; ++i) {
        *dst++ = *p_src--;
    }
}

#ifdef __clang__
extern void explicit_bzero(void *ptr, size_t len);
#endif
/**
 * Wrapper for explicit_bzero() supperssing "implicit function declaration" warning.
 *
 * @param[out] dest
 *   Buffer that needs to be zeroized.
 * @param[in] len
 *   Size of the buffer in bytes.
 */
static inline void call_explicit_bzero(void *dest, size_t len) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    explicit_bzero(dest, len);
#pragma GCC diagnostic pop
}

/**
 * Tests two blocks of memory for equality.
 *
 * This is a wrapper for memcmp() returning a boolean value instead of an integer.
 *
 * @param[in] ptr1
 *   Pointer to block of memory.
 * @param[in] ptr2
 *   Pointer to block of memory.
 * @param[in] num
 *   Number of bytes to compare.
 *
 * @return true if blocks are equal, false otherwise.
 */
static inline bool memeq(const void * ptr1, const void * ptr2, size_t num) {
    return 0 == memcmp(ptr1, ptr2, num);
}

/**
 * Tests two null-terminated strings for equality.
 *
 * This is a wrapper for strncmp() returning a boolean value instead of an integer.
 * This function starts comparing the first character of each string. If they are equal to each
 * other, it continues with the following pairs until the characters differ, until a terminating
 * null-character is reached, or until num characters match in both strings, whichever happens
 * first.
 *
 * @param[in] str1
 *   Null-terminated string to be compared.
 * @param[in] str2
 *   Null-terminated string to be compared.
 * @param[in] num
 *   Maximum number of characters to compare.
 *
 * @return true if strings are equal, false otherwise.
 */
static inline bool streq(const char * str1, const char * str2, size_t num) {
    return 0 == strncmp(str1, str2, num);
}
