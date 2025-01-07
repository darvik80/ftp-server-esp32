//
// Created by darvik on 29.12.2024.
//

#pragma once

#include <esp_err.h>
#include <esp_http_client.h>

#include "oss_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oss_client* oss_client_handler_t;

esp_err_t oss_client_create(const oss_config_t* config, oss_client_handler_t* handler);

void oss_client_destroy(oss_client_handler_t handler);

esp_err_t oss_client_get(oss_client_handler_t handler, const char* file_path, http_event_handle_cb callback);

#ifdef __cplusplus
}
#endif