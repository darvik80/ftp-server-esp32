/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "http_utils.h"

#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

#ifndef mem_check
#define mem_check(x) assert(x)
#endif

const char* g_s_wday[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

const char* g_s_mon[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

const char g_s_gmt_format[] = "%s, %.2d %s %.4d %.2d:%.2d:%.2d GMT";

const char g_s_ios8601_format[] = "%.4d%.2d%.2dT%.2d%.2d%.2dZ";

char *http_utils_join_string(const char *first_str, size_t len_first, const char *second_str, size_t len_second)
{
    size_t first_str_len = len_first > 0 ? len_first : strlen(first_str);
    size_t second_str_len = len_second > 0 ? len_second : strlen(second_str);
    char *ret = NULL;
    if (first_str_len + second_str_len > 0) {
        ret = calloc(1, first_str_len + second_str_len + 1);
        mem_check(ret);
        memcpy(ret, first_str, first_str_len);
        memcpy(ret + first_str_len, second_str, second_str_len);
    }
    return ret;
}

char *http_utils_assign_string(char **str, const char *new_str, int len)
{
    int l = len;
    if (new_str == NULL) {
        return NULL;
    }
    char *old_str = *str;
    if (l < 0) {
        l = strlen(new_str);
    }
    if (old_str) {
        old_str = realloc(old_str, l + 1);
        mem_check(old_str);
        old_str[l] = 0;
    } else {
        old_str = calloc(1, l + 1);
        mem_check(old_str);
    }
    memcpy(old_str, new_str, l);
    *str = old_str;
    return old_str;
}

char *http_utils_append_string(char **str, const char *new_str, int len)
{
    int l = len;
    int old_len = 0;
    char *old_str = *str;
    if (new_str != NULL) {
        if (l < 0) {
            l = strlen(new_str);
        }
        if (old_str) {
            old_len = strlen(old_str);
            old_str = realloc(old_str, old_len + l + 1);
            mem_check(old_str);
            old_str[old_len + l] = 0;
        } else {
            old_str = calloc(1, l + 1);
            mem_check(old_str);
        }
        memcpy(old_str + old_len, new_str, l);
        *str = old_str;
    }
    return old_str;
}

void http_utils_trim_whitespace(char **str)
{
    char *end, *start;
    if (str == NULL) {
        return;
    }
    start = *str;
    if (start == NULL) {
        return;
    }
    // Trim leading space
    while (isspace((unsigned char)*start)) start ++;

    if (*start == 0) {  // All spaces?
        **str = 0;
        return;
    }

    // Trim trailing space
    end = (char *)(start + strlen(start) - 1);
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }

    // Write new null terminator
    *(end + 1) = 0;
    memmove(*str, start, strlen(start) + 1);
}

char *http_utils_get_string_between(const char *str, const char *begin, const char *end)
{
    char *found = strcasestr(str, begin);
    char *ret = NULL;
    if (found) {
        found += strlen(begin);
        char *found_end = strcasestr(found, end);
        if (found_end) {
            ret = calloc(1, found_end - found + 1);
            mem_check(ret);
            memcpy(ret, found, found_end - found);
            return ret;
        }
    }
    return NULL;
}

char *http_utils_get_string_after(const char *str, const char *begin)
{
    char *found = strcasestr(str, begin);
    char *ret = NULL;
    if (found) {
        found += strlen(begin);
        char *found_end = (char *)str + strlen(str);
        if (found_end) {
            ret = calloc(1, found_end - found + 1);
            mem_check(ret);
            memcpy(ret, found, found_end - found);
            return ret;
        }
    }
    return NULL;
}

int http_utils_str_starts_with(const char *str, const char *start)
{
    int i;
    int match_str_len = strlen(str);
    int start_len = strlen(start);

    if (start_len > match_str_len) {
        return -1;
    }
    for (i = 0; i < start_len; i++) {
        if (tolower(str[i]) != tolower(start[i])) {
            return 1;
        }
    }
    return 0;
}

/* Converts a hex character to its integer value */
char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *http_url_encode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr) {
        if (isalnum((int)*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
            *pbuf++ = *pstr;
        else if (*pstr == ' ')
            *pbuf++ = '+';
        else
            *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

esp_err_t utils_encode_hex(char* dest, const void* src, int srclen, int* len)
{
    static const char hex_table[] = "0123456789abcdef";
    const unsigned char* in = src;
    int size;

    if (!src) {
        return ESP_ERR_INVALID_ARG;
    }

    if (dest) {
        for (size = 0; size < srclen; size++) {
            *dest++ = hex_table[in[size] >> 4];
            *dest++ = hex_table[in[size] & 0xf];
        }
        *dest = '\0';
    }

    if (len) {
        *len = srclen * 2 + 1;
    }

    return ESP_OK;
}

esp_err_t utils_hmac_sha1(const char* msg, const char* key, uint8_t output[SHA1_DIGEST_SIZE]) {
    //iot_sha256_context context{};
    uint8_t k_ipad[SHA1_KEY_IOPAD_SIZE];    /* inner padding - key XORd with ipad  */
    uint8_t k_opad[SHA1_KEY_IOPAD_SIZE];    /* outer padding - key XORd with opad */
    int32_t i;

    size_t msg_len = strlen(msg);
    size_t key_len = strlen(key);

    if (!msg_len || !key_len) {
        return ESP_ERR_INVALID_ARG;
    }

    if (key_len > SHA1_KEY_IOPAD_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key,key_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < SHA1_KEY_IOPAD_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    mbedtls_sha1_context context;
    mbedtls_sha1_init(&context);
    mbedtls_sha1_starts(&context);
    mbedtls_sha1_update(&context, k_ipad, SHA1_KEY_IOPAD_SIZE);
    mbedtls_sha1_update(&context, (const unsigned char *) msg, msg_len);
    mbedtls_sha1_finish(&context, output);

    /* perform outer SHA */
    mbedtls_sha1_init(&context);
    mbedtls_sha1_starts(&context);
    mbedtls_sha1_update(&context, k_opad, SHA1_KEY_IOPAD_SIZE);    /* start with outer pad */
    mbedtls_sha1_update(&context, output, SHA1_DIGEST_SIZE);     /* then results of 1st hash */
    mbedtls_sha1_finish(&context, output);                       /* finish up 2nd pass */

    return ESP_OK;
}

esp_err_t utils_hmac_sha256(const char* msg, size_t msg_len, const char* key, size_t key_len, uint8_t output[32]) {
    //iot_sha256_context context{};
    uint8_t k_ipad[SHA256_KEY_IOPAD_SIZE];    /* inner padding - key XORd with ipad  */
    uint8_t k_opad[SHA256_KEY_IOPAD_SIZE];    /* outer padding - key XORd with opad */
    int32_t i;

    if (!msg_len || !key_len) {
        return ESP_ERR_INVALID_ARG;
    }

    if (key_len > SHA256_KEY_IOPAD_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < SHA256_KEY_IOPAD_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts(&context, 0);
    mbedtls_sha256_update(&context, k_ipad, SHA256_KEY_IOPAD_SIZE);
    mbedtls_sha256_update(&context, (const unsigned char *) msg, msg_len);
    mbedtls_sha256_finish(&context, output);

    /* perform outer SHA */
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts(&context, 0);
    mbedtls_sha256_update(&context, k_opad, SHA256_KEY_IOPAD_SIZE);    /* start with outer pad */
    mbedtls_sha256_update(&context, output, SHA256_DIGEST_SIZE);     /* then results of 1st hash */
    mbedtls_sha256_finish(&context, output);                       /* finish up 2nd pass */

    return ESP_OK;
}

void utils_SHA256(const char* msg, size_t len, uint8_t hash[32])
{
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts(&context, 0);
    mbedtls_sha256_update(&context, (const unsigned char*)msg, len);
    mbedtls_sha256_finish(&context, hash);
}

bool utils_has_suffix(const char *string, const char *ending)
{
    const char *str = string;
    const char *suffix = ending;

    for (;;) {                          /* loop continually to evaluate end of string */
        if (*str == *suffix) {
            suffix++;
        }
        else {
            suffix = ending;
        }
        str++;

        if (!*str && !*suffix) {        /* if at end of both, return true */
            return true;
        }

        if (!*str) {               /* if at end of str, break, returning false */
            break;
        }
    }

    return false;
}

#define AOS_MAX_SHORT_TIME_LEN 10

esp_err_t  utils_get_gmt_time_date(const char *gmt, char datestr[10])
{
    char week[4];
    char month[4];
    struct tm t;
    if (!gmt) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(week,0,4);
    memset(month,0,4);

    sscanf(gmt,"%3s, %2d %3s %4d %2d:%2d:%2d GMT",
        week, &t.tm_mday, month, &t.tm_year,
        &t.tm_hour, &t.tm_min, &t.tm_sec);

    t.tm_mon = 0;
    for (int i = 0; i < 12; i++) {
        if (strcmp(g_s_mon[i], month) == 0) {
            t.tm_mon = i + 1;
            break;
        }
    }
   snprintf(datestr, AOS_MAX_SHORT_TIME_LEN, "%.4d%.2d%.2d", t.tm_year, t.tm_mon, t.tm_mday);

    return ESP_OK;
}

char* utils_to_lower(char* s)
{
    for (char* p = s; *p; p++) *p = tolower(*p);
    return s;
}