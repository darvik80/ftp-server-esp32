/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "esp_err.h"
#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct properties* properties_handle_t;

/**
* dictionary item struct, with key-value pair
*/
typedef struct property
{
    char* key; /*!< key */
    char* value; /*!< value */
    STAILQ_ENTRY(property) next; /*!< Point to next entry */
} property_t;

STAILQ_HEAD(properties, property);

typedef struct property* property_handle_t;

properties_handle_t properties_create();

esp_err_t properties_clean(properties_handle_t header);

void properties_destroy(properties_handle_t header);

esp_err_t properties_set(properties_handle_t header, const char* key, const char* value);

int properties_set_format(properties_handle_t header, const char* key, const char* format, ...);

esp_err_t properties_get(properties_handle_t header, const char* key, char** value);

char* properties_get_value(properties_handle_t header, const char* key);

int properties_generate_string(properties_handle_t header, int index, char* buffer, int* buffer_len);

esp_err_t properties_delete(properties_handle_t header, const char* key);

int properties_is_empty(properties_handle_t props);

property_handle_t properties_get_next(properties_handle_t props, property_handle_t cur);

size_t properties_count(properties_handle_t props);

#ifdef __cplusplus
}
#endif
