/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "sys/socket.h"
#include "esp_rom_md5.h"
#include "esp_tls_crypto.h"
#include "mbedtls/sha256.h"

#include "esp_log.h"
#include "esp_check.h"

#include "http_utils.h"
#include "http_auth.h"

#include <sys/param.h>

#include "http_client.h"

#define MD5_MAX_LEN (33)
#define SHA256_LEN (32)
#define SHA256_HEX_LEN (65)
#define HTTP_AUTH_BUF_LEN (1024)

static const char *TAG = "HTTP_AUTH";

/**
 * @brief      This function hash a formatted string with MD5 and format the result as ascii characters
 *
 * @param      md         The buffer will hold the ascii result
 * @param[in]  fmt        The format
 *
 * @return     Length of the result
 */
static int md5_printf(char *md, const char *fmt, ...)
{
    unsigned char *buf;
    unsigned char digest[MD5_MAX_LEN];
    int len, i;
    md5_context_t md5_ctx;
    va_list ap;
    va_start(ap, fmt);
    len = vasprintf((char **)&buf, fmt, ap);
    if (buf == NULL) {
        va_end(ap);
        return ESP_FAIL;
    }

    esp_rom_md5_init(&md5_ctx);
    esp_rom_md5_update(&md5_ctx, buf, len);
    esp_rom_md5_final(digest, &md5_ctx);

    for (i = 0; i < 16; ++i) {
        sprintf(&md[i * 2], "%02x", (unsigned int)digest[i]);
    }
    va_end(ap);

    free(buf);
    return MD5_MAX_LEN;
}

/**
 * @brief      This function hash a formatted string with SHA256 and format the result as ascii characters
 *
 * @param      sha          The buffer will hold the ascii result
 * @param[in]  fmt          The format
 *
 * @return     Length of the result
 */
static int sha256_sprintf(char *sha, const char *fmt, ...)
{

    unsigned char *buf;
    unsigned char digest[SHA256_LEN];
    int len, i;
    va_list ap;
    va_start(ap, fmt);
    len = vasprintf((char **)&buf, fmt, ap);
    if (buf == NULL) {
        va_end(ap);
        return ESP_FAIL;
    }

    int ret = 0;
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    if (mbedtls_sha256_starts(&sha256, 0) != 0) {
        goto exit;
    }
    if (mbedtls_sha256_update(&sha256, buf, len) != 0) {
        goto exit;
    }
    if (mbedtls_sha256_finish(&sha256, digest) != 0) {
        goto exit;
    }

    for (i = 0; i < 32; ++i) {
        sprintf(&sha[i * 2], "%02x", (unsigned int)digest[i]);
    }
    sha[SHA256_HEX_LEN - 1] = '\0';
    ret = SHA256_HEX_LEN;

exit:
    free(buf);
    mbedtls_sha256_free(&sha256);
    va_end(ap);
    return ret;
}

char *http_auth_digest(const char *username, const char *password, esp_http_auth_data_t *auth_data)
{
    char *ha1, *ha2 = NULL;
    char *digest = NULL;
    char *auth_str = NULL;
    char *temp_auth_str = NULL;
    esp_err_t ret = ESP_OK;

    if (username == NULL ||
            password == NULL ||
            auth_data->nonce == NULL ||
            auth_data->uri == NULL ||
            auth_data->realm == NULL) {
        return NULL;
    }

    int digest_size = MD5_MAX_LEN;
    int (*digest_func)(char *digest, const char *fmt, ...) = md5_printf;
    if (!memcmp(auth_data->algorithm, "SHA256", strlen("SHA256")) ||
            !memcmp(auth_data->algorithm, "SHA-256", strlen("SHA-256"))) {
        digest_size = SHA256_HEX_LEN;
        digest_func = sha256_sprintf;
    }

    ha1 = calloc(1, digest_size);
    ESP_GOTO_ON_FALSE(ha1, ESP_FAIL, _digest_exit, TAG, "Memory exhausted");

    ha2 = calloc(1, digest_size);
    ESP_GOTO_ON_FALSE(ha2, ESP_FAIL, _digest_exit, TAG, "Memory exhausted");

    digest = calloc(1, digest_size);
    ESP_GOTO_ON_FALSE(digest, ESP_FAIL, _digest_exit, TAG, "Memory exhausted");

    if (digest_func(ha1, "%s:%s:%s", username, auth_data->realm, password) <= 0) {
        goto _digest_exit;
    }

    ESP_LOGD(TAG, "%s %s %s %s", "Digest", username, auth_data->realm, password);
    if ((strcasecmp(auth_data->algorithm, "md5-sess") == 0) ||
            (strcasecmp(auth_data->algorithm, "SHA256") == 0) ||
            (strcasecmp(auth_data->algorithm, "md5-sess") == 0)) {
        if (digest_func(ha1, "%s:%s:%016llx", ha1, auth_data->nonce, auth_data->cnonce) <= 0) {
            goto _digest_exit;
        }
    }
    if (digest_func(ha2, "%s:%s", auth_data->method, auth_data->uri) <= 0) {
        goto _digest_exit;
    }

    //support qop = auth
    if (auth_data->qop && strcasecmp(auth_data->qop, "auth-int") == 0) {
        if (digest_func(ha2, "%s:%s", ha2, "entity") <= 0) {
            goto _digest_exit;
        }
    }

    if (auth_data->qop) {
        // response=digest_func(HA1:nonce:nonceCount:cnonce:qop:HA2)
        if (digest_func(digest, "%s:%s:%08x:%016llx:%s:%s", ha1, auth_data->nonce, auth_data->nc, auth_data->cnonce, auth_data->qop, ha2) <= 0) {
            goto _digest_exit;
        }
    } else {
        /* Although as per RFC-2617, "qop" directive is optional in order to maintain backward compatibality, it is recommended
           to use it if the server indicated that qop is supported. This enhancement was introduced to protect against attacks
           like chosen-plaintext attack. */
        ESP_LOGW(TAG, "\"qop\" directive not found. This may lead to attacks like chosen-plaintext attack");
        // response=digest_func(HA1:nonce:HA2)
        if (digest_func(digest, "%s:%s:%s", ha1, auth_data->nonce, ha2) <= 0) {
            goto _digest_exit;
        }
    }
    int rc = asprintf(&auth_str, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", algorithm=%s, "
                      "response=\"%s\"", username, auth_data->realm, auth_data->nonce, auth_data->uri, auth_data->algorithm, digest);
    if (rc < 0) {
        ESP_LOGE(TAG, "asprintf() returned: %d", rc);
        ret = ESP_FAIL;
        goto _digest_exit;
    }

    if (auth_data->qop) {
        rc = asprintf(&temp_auth_str, ", qop=%s, nc=%08x, cnonce=\"%016"PRIx64"\"", auth_data->qop, auth_data->nc, auth_data->cnonce);
        if (rc < 0) {
            ESP_LOGE(TAG, "asprintf() returned: %d", rc);
            ret = ESP_FAIL;
            goto _digest_exit;
        }
        auth_str = http_utils_append_string(&auth_str, temp_auth_str, strlen(temp_auth_str));
        if (!auth_str) {
            ret = ESP_FAIL;
            goto _digest_exit;
        }
        free(temp_auth_str);
        auth_data->nc ++;
    }
    if (auth_data->opaque) {
        rc = asprintf(&temp_auth_str, "%s, opaque=\"%s\"", auth_str, auth_data->opaque);
        // Free the previous memory allocated for `auth_str`
        free(auth_str);
        if (rc < 0) {
            ESP_LOGE(TAG, "asprintf() returned: %d", rc);
            ret = ESP_FAIL;
            goto _digest_exit;
        }
        auth_str = temp_auth_str;
    }
_digest_exit:
    free(ha1);
    free(ha2);
    free(digest);
    return (ret == ESP_OK) ? auth_str : NULL;
}

char *http_auth_basic(const char *username, const char *password)
{
    size_t out;
    char *user_info = NULL;
    char *digest = NULL;
    esp_err_t ret = ESP_OK;
    size_t n = 0;
    if (asprintf(&user_info, "%s:%s", username, password) < 0) {
        return NULL;
    }
    ESP_RETURN_ON_FALSE(user_info, NULL, TAG, "Memory exhausted");
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));
    digest = calloc(1, 6 + n + 1);
    ESP_GOTO_ON_FALSE(digest, ESP_FAIL, _basic_exit, TAG, "Memory exhausted");
    strcpy(digest, "Basic ");
    esp_crypto_base64_encode((unsigned char *)digest + 6, n, &out, (const unsigned char *)user_info, strlen(user_info));
_basic_exit:
    free(user_info);
    return (ret == ESP_OK) ? digest : NULL;
}

extern const char* HTTP_METHOD_MAPPING[];

const char OSS_CANNONICALIZED_HEADER_PREFIX[] = "x-oss-";
const char OSS_CANNONICALIZED_HEADER_DATE[] = "x-oss-date";
const char OSS_CANNONICALIZED_HEADER_ACL[] = "x-oss-acl";
const char OSS_CANNONICALIZED_HEADER_STORAGE_CLASS[] = "StorageClass";
const char OSS_CANNONICALIZED_HEADER_COPY_SOURCE[] = "x-oss-copy-source";
const char OSS_CANNONICALIZED_HEADER_SYMLINK[] = "x-oss-symlink-target";
const char OSS_CANNONICALIZED_HEADER_REGION[] = "x-oss-bucket-region";
const char OSS_CANNONICALIZED_HEADER_OBJECT_ACL[] = "x-oss-object-acl";
const char OSS_CONTENT_MD5[] = "Content-MD5";
const char OSS_CONTENT_TYPE[] = "Content-Type";
const char OSS_CONTENT_LENGTH[] = "Content-Length";
const char OSS_DATE[] = "Date";
const char OSS_AUTHORIZATION[] = "Authorization";
const char OSS_ACCESSKEYID[] = "OSSAccessKeyId";
const char OSS_EXPECT[] = "Expect";
const char OSS_EXPIRES[] = "Expires";
const char OSS_SIGNATURE[] = "Signature";
const char OSS_ACL[] = "acl";
const char OSS_LOCATION[] = "location";
const char OSS_BUCKETINFO[] = "bucketInfo";
const char OSS_BUCKETSTAT[] = "stat";
const char OSS_RESTORE[] = "restore";
const char OSS_SYMLINK[] = "symlink";
const char OSS_QOS[] = "qos";
const char OSS_PREFIX[] = "prefix";
const char OSS_DELIMITER[] = "delimiter";
const char OSS_MARKER[] = "marker";
const char OSS_MAX_KEYS[] = "max-keys";
const char OSS_UPLOADS[] = "uploads";
const char OSS_UPLOAD_ID[] = "uploadId";
const char OSS_MAX_PARTS[] = "max-parts";
const char OSS_PART_NUMBER_MARKER[] = "part-number-marker";
const char OSS_KEY_MARKER[] = "key-marker";
const char OSS_UPLOAD_ID_MARKER[] = "upload-id-marker";
const char OSS_MAX_UPLOADS[] = "max-uploads";
const char OSS_PARTNUMBER[] = "partNumber";
const char OSS_APPEND[] = "append";
const char OSS_POSITION[] = "position";
const char OSS_MULTIPART_CONTENT_TYPE[] = "application/x-www-form-urlencoded";
const char OSS_COPY_SOURCE[] = "x-oss-copy-source";
const char OSS_COPY_SOURCE_RANGE[] = "x-oss-copy-source-range";
const char OSS_SECURITY_TOKEN[] = "security-token";
const char OSS_STS_SECURITY_TOKEN[] = "x-oss-security-token";
const char OSS_OBJECT_TYPE[] = "x-oss-object-type";
const char OSS_NEXT_APPEND_POSITION[] = "x-oss-next-append-position";
const char OSS_HASH_CRC64_ECMA[] = "x-oss-hash-crc64ecma";
const char OSS_CALLBACK[] = "x-oss-callback";
const char OSS_CALLBACK_VAR[] = "x-oss-callback-var";
const char OSS_PROCESS[] = "x-oss-process";
const char OSS_LIFECYCLE[] = "lifecycle";
const char OSS_REFERER[] = "referer";
const char OSS_CORS[] = "cors";
const char OSS_WEBSITE[] = "website";
const char OSS_LOGGING[] = "logging";
const char OSS_DELETE[] = "delete";
const char OSS_YES[] = "yes";
const char OSS_OBJECT_TYPE_NORMAL[] = "Normal";
const char OSS_OBJECT_TYPE_APPENDABLE[] = "Appendable";
const char OSS_LIVE_CHANNEL[] = "live";
const char OSS_LIVE_CHANNEL_STATUS[] = "status";
const char OSS_COMP[] = "comp";
const char OSS_LIVE_CHANNEL_STAT[] = "stat";
const char OSS_LIVE_CHANNEL_HISTORY[] = "history";
const char OSS_LIVE_CHANNEL_VOD[] = "vod";
const char OSS_LIVE_CHANNEL_START_TIME[] = "startTime";
const char OSS_LIVE_CHANNEL_END_TIME[] = "endTime";
const char OSS_PLAY_LIST_NAME[] = "playlistName";
const char LIVE_CHANNEL_STATUS_DISABLED[] = "disabled";
const char LIVE_CHANNEL_STATUS_ENABLED[] = "enabled";
const char LIVE_CHANNEL_STATUS_IDLE[] = "idle";
const char LIVE_CHANNEL_STATUS_LIVE[] = "live";
const char LIVE_CHANNEL_DEFAULT_TYPE[] = "HLS";
const char LIVE_CHANNEL_DEFAULT_PLAYLIST[] = "playlist.m3u8";
const int LIVE_CHANNEL_DEFAULT_FRAG_DURATION = 5;
const int LIVE_CHANNEL_DEFAULT_FRAG_COUNT = 3;
const int OSS_MAX_PART_NUM = 10000;
const int OSS_PER_RET_NUM = 1000;
const int MAX_SUFFIX_LEN = 1024;
const char OSS_OBJECT_META[] = "objectMeta";
const char OSS_SELECT_OBJECT_OUTPUT_RAW[] = "x-oss-select-output-raw";
const char OSS_TAGGING[] = "tagging";
const char OSS_SIGN_ORIGIN_ONLY[] = "x-oss-sign-origin-only";
const char OSS_CONTENT_SHA256[] = "x-oss-content-sha256";
const char OSS_SECURITY_TOKEN_V4[] = "x-oss-security-token";
const char OSS_SIGNATURE_VERSION[] = "x-oss-signature-version";
const char OSS_CREDENTIAL[] = "x-oss-credential";

const char OSS_EXPIRES_V4[] = "x-oss-expires";
const char OSS_SIGNATURE_V4[] = "x-oss-signature";

#define AOS_SHA256_HASH_LEN 32

#define AOS_MAX_HEADER_LEN 8192
#define AOS_MAX_QUERY_ARG_LEN 1024

#define AOS_MD5_STRING_LEN 32
#define AOS_MAX_URI_LEN 2048
#define AOS_MAX_GMT_TIME_LEN 128
#define AOS_MAX_SHORT_TIME_LEN 10

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

esp_err_t oss_build_canonical_request_v4(oss_http_request_t* req, char** out)
{
    int pos;
    const char* value;
    char* signbuf;
    //const aos_array_header_t* arr;
    //const aos_table_entry_t* elts;
    //aos_table_t* canon_querys;
    //aos_table_t* canon_headers;

    signbuf = malloc(1024);

    //http method + "\n"
    value = HTTP_METHOD_MAPPING[req->method];
    http_utils_append_string(&signbuf, value, strlen(value));
    http_utils_append_string(&signbuf, "\n", 1);

    //Canonical URI + "\n"
    http_utils_append_string(&signbuf, "/", 1);
    if (req->resource != NULL)
    {
        char* canon_buf = http_url_encode(req->resource);
        http_utils_append_string(&signbuf, canon_buf, strlen(canon_buf));
        free(canon_buf);
    }
    http_utils_append_string(&signbuf, "\n", 1);

    //Canonical Query String + "\n"
    int canon_count = 0;
    property_t* canon_querys = calloc(properties_count(req->params), sizeof(property_t));
    for (property_handle_t cur = properties_get_next(req->params, NULL); cur; cur = properties_get_next(
             req->params, cur))
    {
        canon_querys[canon_count].key = http_url_encode(cur->key);
        canon_querys[canon_count++].value = http_url_encode(cur->value);
    }
    qsort(canon_querys, canon_count, sizeof(property_t), cmp_table_key_v4);

    for (pos = 0; pos < canon_count; ++pos)
    {
        if (pos != 0)
        {
            http_utils_append_string(&signbuf, "&", 1);
        }
        http_utils_append_string(&signbuf, canon_querys[pos].key, -1);

        if (value != NULL && *value != '\0')
        {
            http_utils_append_string(&signbuf, "=", 1);
            http_utils_append_string(&signbuf, canon_querys[pos].value, -1);
        }
        free(canon_querys[pos].key);
        free(canon_querys[pos].value);
    }
    free(canon_querys);

    http_utils_append_string(&signbuf, "\n", 1);

    //Canonical Headers + "\n"
    int headers_count = 0;
    property_t* canon_headers = calloc(properties_count(req->headers), sizeof(property_t));
    for (property_handle_t cur = properties_get_next(req->headers, NULL); cur; cur = properties_get_next(
             req->headers, cur))
    {
        if (is_oss_signed_header_v4(cur->key))
        {
            canon_headers[headers_count].key = utils_to_lower(strdup(cur->key));
            http_utils_trim_whitespace(&canon_headers[headers_count].key);
            canon_headers[headers_count].value = strdup(cur->value);
            http_utils_trim_whitespace(&canon_headers[headers_count].value);
            ++headers_count;
        }
    }
    qsort(canon_headers, headers_count, sizeof(property_t), cmp_table_key_v4);
    for (pos = 0; pos < headers_count; ++pos)
    {
        http_utils_append_string(&signbuf, canon_headers[pos].key, -1);
        http_utils_append_string(&signbuf, ":", 1);
        http_utils_append_string(&signbuf, canon_headers[pos].value, -1);
        http_utils_append_string(&signbuf, "\n", 1);

        free(canon_headers[pos].key);
        free(canon_headers[pos].value);
    }
    http_utils_append_string(&signbuf, "\n\n", 2);
    free(canon_headers);

    if ((value = properties_get_value(req->headers, OSS_CONTENT_SHA256)) == NULL)
    {
        http_utils_append_string(&signbuf, "UNSIGNED-PAYLOAD", 16);
    }
    else
    {
        http_utils_append_string(&signbuf, value, -1);
    }

    *out = signbuf;

    return ESP_OK;
}

static int oss_build_string_to_sign_v4(const char* datetime, const char* date,
                                       const char* region, const char* product,
                                       const char* canonical_request, char** out)
{
    uint8_t hash[AOS_SHA256_HASH_LEN];
    char hex[AOS_SHA256_HASH_LEN * 2 + 1];
    char* signbuf = malloc(256);

    // OSS4-HMAC-SHA256 + \n +
    // dateime + \n +
    // data/region/product/aliyun_v4_request + \n +
    // toHex(sha256(canonical_request));
    http_utils_append_string(&signbuf, "OSS4-HMAC-SHA256", 16);
    http_utils_append_string(&signbuf, "\n", 1);
    http_utils_append_string(&signbuf, datetime, -1);
    http_utils_append_string(&signbuf, "\n", 1);

    //scope
    http_utils_append_string(&signbuf, date, -1);
    http_utils_append_string(&signbuf, "/", 1);
    http_utils_append_string(&signbuf, region, -1);
    http_utils_append_string(&signbuf, "/", 1);
    http_utils_append_string(&signbuf, product, -1);
    http_utils_append_string(&signbuf, "/", 1);
    http_utils_append_string(&signbuf, "aliyun_v4_request", 17);
    http_utils_append_string(&signbuf, "\n", 1);

    utils_SHA256(canonical_request, strlen(canonical_request), hash);
    utils_encode_hex(hex, hash, AOS_SHA256_HASH_LEN, NULL);
    http_utils_append_string(&signbuf, hex, AOS_SHA256_HASH_LEN * 2);

    // result
    *out = signbuf;

    return ESP_OK;
}

static int oss_build_signing_key_v4(const char* access_key_secret, const char* date,
                                    const char* region, const char* product, uint8_t signing_key[AOS_SHA256_HASH_LEN])
{
    char signing_secret[64];
    uint8_t signing_date[AOS_SHA256_HASH_LEN];
    uint8_t signing_region[AOS_SHA256_HASH_LEN];
    uint8_t signing_product[AOS_SHA256_HASH_LEN];
    sprintf(signing_secret, "aliyun_v4%s", access_key_secret);
    utils_hmac_sha256(signing_secret, strlen(signing_secret), date, strlen(date), signing_date);
    utils_hmac_sha256((char*)signing_date, AOS_SHA256_HASH_LEN, region, strlen(region), signing_region);
    utils_hmac_sha256((char*)signing_region, AOS_SHA256_HASH_LEN, product, strlen(product), signing_product);
    utils_hmac_sha256((char*)signing_product, AOS_SHA256_HASH_LEN, "aliyun_v4_request", 17, signing_key);

    return ESP_OK;
}

static int oss_build_signature_v4(const uint8_t signing_key[AOS_SHA256_HASH_LEN], const char* string_to_sign,
                                  char** out)
{
    uint8_t signature[AOS_SHA256_HASH_LEN];
    char* signbuf = malloc(AOS_SHA256_HASH_LEN * 2 + 1);
    bzero(signbuf, AOS_SHA256_HASH_LEN * 2 + 1);
    utils_hmac_sha256((const char*)signing_key, AOS_SHA256_HASH_LEN, string_to_sign, strlen(string_to_sign), signature);
    utils_encode_hex(signbuf, signature, AOS_SHA256_HASH_LEN, NULL);

    *out = signbuf;

    return ESP_OK;
}

esp_err_t oss_sign_request(oss_http_request_t* req, const oss_config_t* config)
{
    uint8_t signing_key[AOS_SHA256_HASH_LEN];
    esp_err_t res = ESP_OK;
    // aos_string_t gmt_suffix;
    char shortdate[AOS_MAX_SHORT_TIME_LEN];

    //default, ex payload, x-oss-date
    properties_set(req->headers, OSS_CONTENT_SHA256, "UNSIGNED-PAYLOAD");

    if (properties_get_value(req->headers, OSS_CANNONICALIZED_HEADER_DATE) == NULL)
    {
        char datestr[AOS_MAX_GMT_TIME_LEN];
        const time_t now = time(NULL);
        struct tm tm = *gmtime(&now);
        snprintf(datestr, AOS_MAX_GMT_TIME_LEN, g_s_ios8601_format,
                 1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        properties_set(req->headers, OSS_CANNONICALIZED_HEADER_DATE, datestr);
    }

    //datetime & date
    char* datetime = properties_get_value(req->headers, OSS_CANNONICALIZED_HEADER_DATE);
    char* date = NULL;
    if (utils_has_suffix(datetime, "GMT"))
    {
        utils_get_gmt_time_date(datetime, shortdate);
        date = shortdate;
    }
    else
    {
        date = datetime;
        date[MIN(8, strlen(datetime))] = 0;
    }

    //region
    const char* region;
    if (strlen(config->cloudbox_id))
    {
        region = config->cloudbox_id;
    }
    else
    {
        region = config->region;
    }

    //product, oss or "oss-cloudbox"
    const char* product;
    if (strlen(config->cloudbox_id))
    {
        product = "oss-cloudbox";
    }
    else
    {
        product = "oss";
    }

    char *canonical_request = NULL, *string_to_sign = NULL, *signature = NULL;
    //canonical request
    oss_build_canonical_request_v4(req, &canonical_request);
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
    properties_set(req->headers, OSS_AUTHORIZATION, result);

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

    return res;
}
