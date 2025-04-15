/**
 * @file fallback_strlcpy.h
 * @brief Provides a portable fallback for `strlcpy()` if the platform does not support it.
 *
 * This header defines an inline implementation of `strlcpy()` if it is not available
 * in the system C library. It is intended to be force-included by the build system
 * on platforms without native `strlcpy` support.
 *
 * @note `strlcpy()` is a BSD function and not part of the standard C library,
 * so many Linux distributions (like glibc-based ones) do not provide it.
 */

#pragma once

#include <string.h>

/**
 * @brief Safely copies a C-string into a destination buffer with truncation.
 *
 * This function copies at most `size - 1` characters from the null-terminated
 * string `src` to `dst`, null-terminating the result if `size > 0`.
 *
 * It returns the total length of the string it tried to create — that is,
 * the length of `src`. If the return value is greater than or equal to `size`,
 * truncation occurred.
 *
 * @param[out] dst
 *   Destination buffer.
 * @param[in] src
 *   Source null-terminated string.
 * @param[in] size
 *   Size of the destination buffer in bytes.
 *
 * @return Length of `src`; this will be >= `size` if truncation occurred.
 *
 * @note This implementation is safe and standard-compliant, but less efficient
 * than optimized versions found in libc replacements like `libbsd`.
 */
static inline size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t copylen = (srclen >= size) ? size - 1 : srclen;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}