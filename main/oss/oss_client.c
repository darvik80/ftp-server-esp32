//
// Created by darvik on 29.12.2024.
//
#include <esp_crt_bundle.h>
#include <esp_log.h>
#include <esp_tls.h>
#include <string.h>
#include "oss_client.h"

#define MAX_HTTP_URI_BUFFER 1024
#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048

const char* OSS_TAG = "oss";

esp_err_t oss_http_event_handler(esp_http_client_event_t* evt)
{
    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGI(OSS_TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGI(OSS_TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADERS_SENT:
        ESP_LOGI(OSS_TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGI(OSS_TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGI(OSS_TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        http_event_handle_cb callback = (http_event_handle_cb)evt->user_data;
        callback(evt);

        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGI(OSS_TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        {
            ESP_LOGI(OSS_TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0)
            {
                ESP_LOGI(OSS_TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(OSS_TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
        }
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGI(OSS_TAG, "HTTP_EVENT_REDIRECT");
        esp_http_client_set_header(evt->client, "From", "user@example.com");
        esp_http_client_set_header(evt->client, "Accept", "text/html");
        esp_http_client_set_redirection(evt->client);
        break;
    }
    return ESP_OK;
}


typedef struct oss_client
{
    oss_config_t config;
    esp_http_client_handle_t http_client;

    properties_handle_t headers;
    properties_handle_t params;
} oss_client_t;

esp_err_t oss_client_create(const oss_config_t* config, oss_client_handler_t* handler)
{
    oss_client_t* client = malloc(sizeof(oss_client_t));
    if (client == NULL)
    {
        return ESP_ERR_NO_MEM;
    }

    client->config.endpoint = strdup(config->endpoint);
    client->config.access_key_id = strdup(config->access_key_id);
    client->config.access_key_secret = strdup(config->access_key_secret);
    client->config.region = strdup(config->region);
    client->config.bucket = strdup(config->bucket);

    client->headers = properties_create();
    client->params = properties_create();

    const esp_http_client_config_t http_config = {
        .url = "https://localhost",
        .event_handler = oss_http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    client->http_client = esp_http_client_init(&http_config);

    *handler = client;

    return ESP_OK;
}

void oss_client_destroy(oss_client_handler_t handler)
{
    free(handler->config.endpoint);
    free(handler->config.access_key_id);
    free(handler->config.access_key_secret);
    free(handler->config.region);
    free(handler->config.bucket);

    properties_destroy(handler->headers);
    properties_destroy(handler->params);
    esp_http_client_cleanup(handler->http_client);
    free(handler);
}

esp_err_t oss_client_get(oss_client_handler_t handler, const char* file_path, http_event_handle_cb callback)
{
    char* url = malloc(MAX_HTTP_URI_BUFFER);
    snprintf(url, MAX_HTTP_URI_BUFFER, "https://%s/%s", handler->config.endpoint, file_path);

    properties_clean(handler->headers);
    properties_clean(handler->params);
    oss_sign_data_t req = {
        .client = handler->http_client,
        .method = HTTP_METHOD_GET,
        .headers = handler->headers,
        .params = handler->params,
        .bucket = handler->config.bucket,
        .file_path = file_path,
    };

    esp_http_client_set_url(handler->http_client, url);
    esp_http_client_set_method(handler->http_client, req.method);
    esp_http_client_set_header(handler->http_client, "Host", handler->config.endpoint);
    free(url);

    oss_sign_request(&req, &handler->config);

    esp_http_client_set_user_data(handler->http_client, callback);
    // GET
    esp_err_t err = esp_http_client_perform(handler->http_client);
    if (err == ESP_OK)
    {
        ESP_LOGI(OSS_TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                 esp_http_client_get_status_code(handler->http_client),
                 esp_http_client_get_content_length(handler->http_client));
    }
    else
    {
        ESP_LOGI(OSS_TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_set_user_data(handler->http_client, NULL);

    return err;
}
