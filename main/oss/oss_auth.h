//
// Created by darvik on 29.12.2024.
//

#pragma once

#include <esp_err.h>
#include <esp_http_client.h>
#include "properties.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const char* endpoint;
    const char* access_key_id;
    const char* access_key_secret;
    const char* region;
    const char* bucket;
} oss_config_t;

typedef struct oss_sign_data
{
    esp_http_client_handle_t client;
    esp_http_client_method_t method;
    properties_handle_t headers;
    properties_handle_t params;
    const char* bucket;
    const char* file_path;
} oss_sign_data_t;

/**
  * @brief  sign oss request
**/
esp_err_t oss_sign_request(oss_sign_data_t* sign_data, const oss_config_t* config);

#ifdef __cplusplus
}
#endif
