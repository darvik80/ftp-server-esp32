/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef _HTTP_UTILS_H_
#define _HTTP_UTILS_H_
#include <esp_err.h>
#include <stdbool.h>
#include <sys/time.h>

extern const char* g_s_wday[];

extern const char* g_s_mon[];

extern const char g_s_gmt_format[];

extern const char g_s_ios8601_format[];

/**
 * @brief      Assign new_str to *str pointer, and realloc *str if it not NULL
 *
 * @param      str      pointer to string pointer
 * @param      new_str  assign this tring to str
 * @param      len      length of string, less than 0 if new_str is zero terminated
 *
 * @return
 *  - new_str pointer
 *  - NULL
 */
char *http_utils_assign_string(char **str, const char *new_str, int len);

/**
 * @brief      Realloc *str and append new_str to it if new_str is not NULL; return *str pointer if new_str is NULL
 *
 * @param      str      pointer to string pointer
 * @param      new_str  append this string to str
 * @param      len      length of string, less than 0 if new_str is zero terminated
 *
 * @return
 *  - *str pointer
 */
char *http_utils_append_string(char **str, const char *new_str, int len);

/**
 * @brief      Remove white space at begin and end of string
 *
 * @param[in]  str   The string
 *
 * @return     New strings have been trimmed
 */
void http_utils_trim_whitespace(char **str);

/**
 * @brief      Gets the string between 2 string.
 *             It will allocate a new memory space for this string, so you need to free it when no longer use
 *
 * @param[in]  str    The source string
 * @param[in]  begin  The begin string
 * @param[in]  end    The end string
 *
 * @return     The string between begin and end
 */
char *http_utils_get_string_between(const char *str, const char *begin, const char *end);

/**
 * @brief      Returns a string that contains the part after the search string till the end of the source string.
 *             It will allocate a new memory space for this string, so you need to free it when no longer used
 *
 * @param[in]  str    The source string
 * @param[in]  begin  The search string
 *
 * @return     The string between begin and the end of str
 */
char *http_utils_get_string_after(const char *str, const char *begin);

/**
 * @brief      Join 2 strings to one
 *             It will allocate a new memory space for this string, so you need to free it when no longer use
 *
 * @param[in]  first_str   The first string
 * @param[in]  len_first   The length first
 * @param[in]  second_str  The second string
 * @param[in]  len_second  The length second
 *
 * @return
 * - New string pointer
 * - NULL: Invalid input
 */
char *http_utils_join_string(const char *first_str, size_t len_first, const char *second_str, size_t len_second);

/**
 * @brief      Check if ``str`` is start with ``start``
 *
 * @param[in]  str    The string
 * @param[in]  start  The start
 *
 * @return
 *     - (-1) if length of ``start`` larger than length of ``str``
 *     - (1) if ``start`` NOT starts with ``start``
 *     - (0) if ``str`` starts with ``start``
 */
int http_utils_str_starts_with(const char *str, const char *start);

char *http_url_encode(char *str);

esp_err_t utils_encode_hex(char* dest, const void* src, int srclen, int* len);

#define SHA1_KEY_IOPAD_SIZE   (64)
#define SHA1_DIGEST_SIZE      (20)

esp_err_t utils_hmac_sha1(const char* msg, const char* key, uint8_t output[SHA1_DIGEST_SIZE]);

#define SHA256_KEY_IOPAD_SIZE   (64)
#define SHA256_DIGEST_SIZE      (32)

esp_err_t utils_hmac_sha256(const char* msg, size_t msg_len, const char* key, size_t key_len, uint8_t output[32]);

void utils_SHA256(const char* msg, size_t len, uint8_t hash[32]);

bool utils_has_suffix(const char *string, const char *ending);

esp_err_t utils_get_gmt_time_date(const char *gmt, char datestr[10]);

char* utils_to_lower(char* s);

#endif
