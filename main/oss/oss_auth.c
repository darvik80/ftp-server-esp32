//
// Created by darvik on 29.12.2024.
//

#include "oss_auth.h"

#include <esp_http_client.h>
#include <esp_log.h>
#include <string.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

#include "oss_utils.h"
#include "properties.h"


#define SHA1_KEY_IOPAD_SIZE   (64)
#define SHA1_DIGEST_SIZE      (20)

#define SHA256_KEY_IOPAD_SIZE   (64)
#define SHA256_DIGEST_SIZE      (32)

#define MAX_GMT_TIME_LEN 128
#define MAX_SHORT_TIME_LEN 10

const char OSS_CANNONICALIZED_HEADER_PREFIX[] = "x-oss-";
const char OSS_CANNONICALIZED_HEADER_DATE[] = "x-oss-date";
const char OSS_CONTENT_MD5[] = "Content-MD5";
const char OSS_CONTENT_TYPE[] = "Content-Type";
const char OSS_CONTENT_LENGTH[] = "Content-Length";
const char OSS_CONTENT_SHA256[] = "x-oss-content-sha256";
const char OSS_AUTHORIZATION[] = "Authorization";

static const char* s_wday[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char* s_mon[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char s_ios8601_format[] = "%.4d%.2d%.2dT%.2d%.2d%.2dZ";

static int cmp_table_key_v4(const void* v1, const void* v2)
{
    const property_t* s1 = v1;
    const property_t* s2 = v2;
    return strcmp(s1->key, s2->key);
}

static int is_oss_signed_header_v4(const char* str)
{
    if (strncasecmp(str, OSS_CANNONICALIZED_HEADER_PREFIX, strlen(OSS_CANNONICALIZED_HEADER_PREFIX)) == 0 ||
        strncasecmp(str, OSS_CONTENT_MD5, strlen(OSS_CONTENT_MD5)) == 0 ||
        strncasecmp(str, OSS_CONTENT_TYPE, strlen(OSS_CONTENT_TYPE)) == 0)
    {
        return 1;
    }
    return 0;
}

/* Converts an integer value to its hex character*/
char to_hex(char code)
{
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

char* url_encode_ex(const char* str, bool slash)
{
    const char* pstr = str;
    char *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr)
    {
        if (isalnum((int)*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
            *pbuf++ = *pstr;
        else if (*pstr == ' ')
        {
            *pbuf++ = '%';
            *pbuf++ = '2';
            *pbuf++ = '0';
        }
        else if (*pstr == '/' && slash)
        {
            *pbuf++ = *pstr;
        }
        else
            *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

char* url_encode(const char* str)
{
    const char* pstr = str;
    char *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr)
    {
        if (isalnum((int)*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
            *pbuf++ = *pstr;
        else if (*pstr == ' ')
        {
            *pbuf++ = '%';
            *pbuf++ = '2';
            *pbuf++ = '0';
        }
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

    if (!src)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (dest)
    {
        for (int size = 0; size < srclen; size++)
        {
            *dest++ = hex_table[in[size] >> 4];
            *dest++ = hex_table[in[size] & 0xf];
        }
        *dest = '\0';
    }

    if (len)
    {
        *len = srclen * 2 + 1;
    }

    return ESP_OK;
}

char* utils_to_lower(char* s)
{
    for (char* p = s; *p; p++) *p = tolower(*p);
    return s;
}

esp_err_t utils_get_gmt_time_date(const char* gmt, char datestr[10])
{
    char week[4];
    char month[4];
    struct tm t;
    if (!gmt)
    {
        return ESP_ERR_INVALID_ARG;
    }
    memset(week, 0, 4);
    memset(month, 0, 4);

    sscanf(gmt, "%3s, %2d %3s %4d %2d:%2d:%2d GMT",
           week, &t.tm_mday, month, &t.tm_year,
           &t.tm_hour, &t.tm_min, &t.tm_sec);

    t.tm_mon = 0;
    for (int i = 0; i < 12; i++)
    {
        if (strcmp(s_mon[i], month) == 0)
        {
            t.tm_mon = i + 1;
            break;
        }
    }
    snprintf(datestr, MAX_SHORT_TIME_LEN, "%.4d%.2d%.2d", t.tm_year, t.tm_mon, t.tm_mday);

    return ESP_OK;
}

esp_err_t utils_hmac_sha1(const char* msg, const char* key, uint8_t output[SHA1_DIGEST_SIZE])
{
    //iot_sha256_context context{};
    uint8_t k_ipad[SHA1_KEY_IOPAD_SIZE]; /* inner padding - key XORd with ipad  */
    uint8_t k_opad[SHA1_KEY_IOPAD_SIZE]; /* outer padding - key XORd with opad */
    int32_t i;

    size_t msg_len = strlen(msg);
    size_t key_len = strlen(key);

    if (!msg_len || !key_len)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (key_len > SHA1_KEY_IOPAD_SIZE)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < SHA1_KEY_IOPAD_SIZE; i++)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    mbedtls_sha1_context context;
    mbedtls_sha1_init(&context);
    mbedtls_sha1_starts(&context);
    mbedtls_sha1_update(&context, k_ipad, SHA1_KEY_IOPAD_SIZE);
    mbedtls_sha1_update(&context, (const unsigned char*)msg, msg_len);
    mbedtls_sha1_finish(&context, output);

    /* perform outer SHA */
    mbedtls_sha1_init(&context);
    mbedtls_sha1_starts(&context);
    mbedtls_sha1_update(&context, k_opad, SHA1_KEY_IOPAD_SIZE); /* start with outer pad */
    mbedtls_sha1_update(&context, output, SHA1_DIGEST_SIZE); /* then results of 1st hash */
    mbedtls_sha1_finish(&context, output); /* finish up 2nd pass */

    return ESP_OK;
}

esp_err_t utils_hmac_sha256(const char* key, size_t key_len, const char* msg, size_t msg_len,
                            uint8_t output[SHA256_DIGEST_SIZE])
{
    uint8_t k_ipad[SHA256_KEY_IOPAD_SIZE]; /* inner padding - key XORd with ipad  */
    uint8_t k_opad[SHA256_KEY_IOPAD_SIZE]; /* outer padding - key XORd with opad */

    if (key_len > SHA256_KEY_IOPAD_SIZE) {
        return false;
    }

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    /* XOR key with ipad and opad values */
    for (int i = 0; i < SHA256_KEY_IOPAD_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts(&context, 0);
    mbedtls_sha256_update(&context, k_ipad, SHA256_KEY_IOPAD_SIZE);
    mbedtls_sha256_update(&context, (const unsigned char*)msg, msg_len);
    mbedtls_sha256_finish(&context, output);

    /* perform outer SHA */
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts(&context, 0);
    mbedtls_sha256_update(&context, k_opad, SHA256_KEY_IOPAD_SIZE); /* start with outer pad */
    mbedtls_sha256_update(&context, output, SHA256_DIGEST_SIZE); /* then results of 1st hash */
    mbedtls_sha256_finish(&context, output); /* finish up 2nd pass */

    return ESP_OK;
}

void utils_SHA256(const char* msg, size_t len, uint8_t output[SHA256_DIGEST_SIZE])
{
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts(&context, 0);
    mbedtls_sha256_update(&context, (const unsigned char*)msg, len);
    mbedtls_sha256_finish(&context, output);
}

bool utils_has_suffix(const char* string, const char* ending)
{
    const char* str = string;
    const char* suffix = ending;

    for (;;)
    {
        /* loop continually to evaluate end of string */
        if (*str == *suffix)
        {
            suffix++;
        }
        else
        {
            suffix = ending;
        }
        str++;

        if (!*str && !*suffix)
        {
            /* if at end of both, return true */
            return true;
        }

        if (!*str)
        {
            /* if at end of str, break, returning false */
            break;
        }
    }

    return false;
}



esp_err_t oss_build_canonical_request_v4(oss_sign_data_t* req, char** out)
{
    int pos;
    char* signbuf = NULL;

    //http method + "\n"
    const char* value;
    switch (req->method)
    {
    case HTTP_METHOD_PUT:
        value = "PUT";
        break;
    case HTTP_METHOD_POST:
        value = "POST";
        break;
    case HTTP_METHOD_GET:
    default:
        value = "GET";
        break;
    }

    oss_utils_append_string(&signbuf, value, strlen(value));
    oss_utils_append_string(&signbuf, "\n", 1);

    //Canonical URI + "\n"
    oss_utils_append_string(&signbuf, "/", 1);
    if (req->bucket != NULL)
    {
        oss_utils_append_string(&signbuf, req->bucket, -1);
        oss_utils_append_string(&signbuf, "/", 1);
    }
    if (req->file_path != NULL)
    {
        char* canon_buf = url_encode_ex(req->file_path, true);
        oss_utils_append_string(&signbuf, canon_buf, strlen(canon_buf));
        free(canon_buf);
    }
    oss_utils_append_string(&signbuf, "\n", 1);

    //Canonical Query String + "\n"
    int canon_count = 0;
    property_t* canon_querys = calloc(properties_count(req->params), sizeof(property_t));
    for (property_handle_t cur = properties_get_next(req->params, NULL); cur; cur = properties_get_next(
             req->params, cur))
    {
        canon_querys[canon_count].key = url_encode(cur->key);
        canon_querys[canon_count++].value = url_encode(cur->value);
    }
    qsort(canon_querys, canon_count, sizeof(property_t), cmp_table_key_v4);

    for (pos = 0; pos < canon_count; ++pos)
    {
        if (pos != 0)
        {
            oss_utils_append_string(&signbuf, "&", 1);
        }
        oss_utils_append_string(&signbuf, canon_querys[pos].key, -1);

        if (value != NULL && *canon_querys[pos].value != 0)
        {
            oss_utils_append_string(&signbuf, "=", 1);
            oss_utils_append_string(&signbuf, canon_querys[pos].value, -1);
        }
        free(canon_querys[pos].key);
        free(canon_querys[pos].value);
    }
    free(canon_querys);

    oss_utils_append_string(&signbuf, "\n", 1);

    //Canonical Headers + "\n"
    int headers_count = 0;
    property_t* canon_headers = calloc(properties_count(req->headers), sizeof(property_t));
    for (property_handle_t cur = properties_get_next(req->headers, NULL); cur; cur = properties_get_next(
             req->headers, cur))
    {
        if (is_oss_signed_header_v4(cur->key))
        {
            canon_headers[headers_count].key = utils_to_lower(strdup(cur->key));
            oss_utils_trim_whitespace(&canon_headers[headers_count].key);
            canon_headers[headers_count].value = strdup(cur->value);
            oss_utils_trim_whitespace(&canon_headers[headers_count].value);
            ++headers_count;
        }
    }
    qsort(canon_headers, headers_count, sizeof(property_t), cmp_table_key_v4);
    for (pos = 0; pos < headers_count; ++pos)
    {
        oss_utils_append_string(&signbuf, canon_headers[pos].key, -1);
        oss_utils_append_string(&signbuf, ":", 1);
        oss_utils_append_string(&signbuf, canon_headers[pos].value, -1);
        oss_utils_append_string(&signbuf, "\n", 1);

        free(canon_headers[pos].key);
        free(canon_headers[pos].value);
    }
    oss_utils_append_string(&signbuf, "\n\n", 2);
    free(canon_headers);

    if ((value = properties_get_value(req->headers, OSS_CONTENT_SHA256)) == NULL)
    {
        oss_utils_append_string(&signbuf, "UNSIGNED-PAYLOAD", 16);
    }
    else
    {
        oss_utils_append_string(&signbuf, value, -1);
    }

    *out = signbuf;

    return ESP_OK;
}

static int oss_build_string_to_sign_v4(const char* datetime, const char* date,
                                       const char* region, const char* product,
                                       const char* canonical_request, char** out)
{
    uint8_t hash[SHA256_DIGEST_SIZE];
    char hex[SHA256_DIGEST_SIZE * 2 + 1];
    utils_SHA256(canonical_request, strlen(canonical_request), hash);
    utils_encode_hex(hex, hash, SHA256_DIGEST_SIZE, NULL);

    *out = (char*)malloc(512);
    snprintf(*out, 512, "OSS4-HMAC-SHA256\n%s\n%s/%s/%s/aliyun_v4_request\n%s", datetime, date, region, product, hex);

    return ESP_OK;
}

static int oss_build_signing_key_v4(const char* access_key_secret, const char* date,
                                    const char* region, const char* product, uint8_t signing_key[SHA256_DIGEST_SIZE])
{
    char signing_secret[64];
    uint8_t signing_date[SHA256_DIGEST_SIZE];
    uint8_t signing_region[SHA256_DIGEST_SIZE];
    uint8_t signing_product[SHA256_DIGEST_SIZE];
    sprintf(signing_secret, "aliyun_v4%s", access_key_secret);
    utils_hmac_sha256(signing_secret, strlen(signing_secret), date, strlen(date), signing_date);
    utils_hmac_sha256((char*)signing_date, SHA256_DIGEST_SIZE, region, strlen(region), signing_region);
    utils_hmac_sha256((char*)signing_region, SHA256_DIGEST_SIZE, product, strlen(product), signing_product);
    utils_hmac_sha256((char*)signing_product, SHA256_DIGEST_SIZE, "aliyun_v4_request", 17, signing_key);

    return ESP_OK;
}

static int oss_build_signature_v4(const uint8_t signing_key[SHA256_DIGEST_SIZE], const char* string_to_sign,
                                  char** out)
{
    uint8_t signature[SHA256_DIGEST_SIZE];
    char* signbuf = malloc(SHA256_DIGEST_SIZE * 2 + 1);
    memset(signbuf, 0, SHA256_DIGEST_SIZE * 2 + 1);
    utils_hmac_sha256((const char*)signing_key, SHA256_DIGEST_SIZE, string_to_sign, strlen(string_to_sign), signature);
    utils_encode_hex(signbuf, signature, SHA256_DIGEST_SIZE, NULL);

    *out = signbuf;

    return ESP_OK;
}

esp_err_t oss_sign_request(oss_sign_data_t* sign_data, const oss_config_t *config)
{
    uint8_t signing_key[SHA256_DIGEST_SIZE];
    esp_err_t res = ESP_OK;

    //default, ex payload, x-oss-date
    properties_set(sign_data->headers, OSS_CONTENT_SHA256, "UNSIGNED-PAYLOAD");
    esp_http_client_set_header(sign_data->client, OSS_CONTENT_SHA256, "UNSIGNED-PAYLOAD");

    char datestr[MAX_GMT_TIME_LEN];
    const time_t now = time(NULL);
    struct tm tm = *gmtime(&now);
    snprintf(datestr, MAX_GMT_TIME_LEN, s_ios8601_format,
             1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

    properties_set(sign_data->headers, OSS_CANNONICALIZED_HEADER_DATE, datestr);
    esp_http_client_set_header(sign_data->client, OSS_CANNONICALIZED_HEADER_DATE, datestr);

    //datetime & date
    char* datetime = properties_get_value(sign_data->headers, OSS_CANNONICALIZED_HEADER_DATE);
    char* date = NULL;
    if (utils_has_suffix(datetime, "GMT"))
    {
        char shortdate[MAX_SHORT_TIME_LEN];
        utils_get_gmt_time_date(datetime, shortdate);
        date = strdup(shortdate);
    }
    else
    {
        date = strdup(datetime);
        date[MIN(8, strlen(datetime))] = 0;
    }

    //region
    const char* region = config->region;

    //product, oss or "oss-cloudbox"
    const char* product = "oss";

    char *canonical_request = NULL, *string_to_sign = NULL, *signature = NULL;
    //canonical request
    oss_build_canonical_request_v4(sign_data, &canonical_request);
    //string to sign
    oss_build_string_to_sign_v4(datetime, date, region, product, canonical_request, &string_to_sign);
    //signing key
    oss_build_signing_key_v4(config->access_key_secret, date, region, product, signing_key);
    //signature
    oss_build_signature_v4(signing_key, string_to_sign, &signature);

    //sign header
    char* result = malloc(256);
    snprintf(result, 256, "OSS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aliyun_v4_request,Signature=%s",
             config->access_key_id,
             date,
             region,
             product,
             signature
    );
    properties_set(sign_data->headers, OSS_AUTHORIZATION, result);
    esp_http_client_set_header(sign_data->client, OSS_AUTHORIZATION, result);

    if (result)
    {
        free(result);
    }

    if (canonical_request)
    {
        free(canonical_request);
    }

    if (string_to_sign)
    {
        free(string_to_sign);
    }

    if (signature)
    {
        free(signature);
    }

    if (date)
    {
        free(date);
    }

    return res;
}