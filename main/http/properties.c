/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "properties.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "esp_log.h"
#include "esp_check.h"
#include "http_utils.h"

static const char* TAG = "PROPS";
#define HEADER_BUFFER (1024)

#ifndef mem_check
#define mem_check(x) assert(x)
#endif

properties_handle_t properties_create(void)
{
    properties_handle_t props = calloc(1, sizeof(struct properties));
    ESP_RETURN_ON_FALSE(props, NULL, TAG, "Memory exhausted");
    STAILQ_INIT(props);
    return props;
}

void properties_destroy(properties_handle_t props)
{
    properties_clean(props);
    free(props);
}

property_handle_t properties_get_item(properties_handle_t props, const char* key)
{
    property_handle_t item;
    if (props == NULL || key == NULL)
    {
        return NULL;
    }
    STAILQ_FOREACH(item, props, next)
    {
        if (strcasecmp(item->key, key) == 0)
        {
            return item;
        }
    }
    return NULL;
}

esp_err_t properties_get(properties_handle_t props, const char* key, char** value)
{
    property_handle_t item = properties_get_item(props, key);
    if (item)
    {
        *value = item->value;
    }
    else
    {
        *value = NULL;
        return ESP_ERR_NOT_FOUND;
    }

    return ESP_OK;
}

char* properties_get_value(properties_handle_t props, const char* key)
{
    char* value;
    if (properties_get(props, key, &value) == ESP_OK)
    {
        return value;
    }

    return NULL;
}

static esp_err_t properties_new_item(properties_handle_t header, const char* key, const char* value)
{
    esp_err_t ret = ESP_OK;
    property_handle_t item;

    item = calloc(1, sizeof(property_t));
    ESP_RETURN_ON_FALSE(item, ESP_ERR_NO_MEM, TAG, "Memory exhausted");
    http_utils_assign_string(&item->key, key, -1);
    ESP_GOTO_ON_FALSE(item->key, ESP_ERR_NO_MEM, _header_new_item_exit, TAG, "Memory exhausted");
    http_utils_trim_whitespace(&item->key);
    http_utils_assign_string(&item->value, value, -1);
    ESP_GOTO_ON_FALSE(item->value, ESP_ERR_NO_MEM, _header_new_item_exit, TAG, "Memory exhausted");
    http_utils_trim_whitespace(&item->value);
    STAILQ_INSERT_TAIL(header, item, next);
    return ret;

_header_new_item_exit:
    free(item->key);
    free(item->value);
    free(item);
    return ret;
}

esp_err_t properties_set(properties_handle_t props, const char* key, const char* value)
{
    property_handle_t item;

    if (value == NULL)
    {
        return properties_delete(props, key);
    }

    item = properties_get_item(props, key);

    if (item)
    {
        free(item->value);
        item->value = strdup(value);
        http_utils_trim_whitespace(&item->value);
        return ESP_OK;
    }
    return properties_new_item(props, key, value);
}

esp_err_t properties_set_from_string(properties_handle_t props, const char* key_value_data)
{
    char* p_str = strdup(key_value_data);
    ESP_RETURN_ON_FALSE(p_str, ESP_ERR_NO_MEM, TAG, "Memory exhausted");
    char* eq_ch = strchr(p_str, ':');
    if (eq_ch == NULL)
    {
        free(p_str);
        return ESP_ERR_INVALID_ARG;
    }
    *eq_ch = 0;

    properties_set(props, p_str, eq_ch + 1);
    free(p_str);
    return ESP_OK;
}


esp_err_t properties_delete(properties_handle_t props, const char* key)
{
    property_handle_t item = properties_get_item(props, key);
    if (item)
    {
        STAILQ_REMOVE(props, item, property, next);
        free(item->key);
        free(item->value);
        free(item);
    }
    else
    {
        return ESP_ERR_NOT_FOUND;
    }
    return ESP_OK;
}


int properties_set_format(properties_handle_t props, const char* key, const char* format, ...)
{
    va_list arg_ptr;
    int len = 0;
    char* buf = NULL;
    va_start(arg_ptr, format);
    len = vasprintf(&buf, format, arg_ptr);
    va_end(arg_ptr);
    ESP_RETURN_ON_FALSE(buf, 0, TAG, "Memory exhausted");
    properties_set(props, key, buf);
    free(buf);
    return len;
}

int properties_generate_string(properties_handle_t props, int index, char* buffer, int* buffer_len)
{
    property_handle_t item;
    int siz = 0;
    int idx = 0;
    int ret_idx = -1;
    bool is_end = false;

    // iterate over the header entries to calculate buffer size and determine last item
    STAILQ_FOREACH(item, props, next)
    {
        if (item->value && idx >= index)
        {
            siz += strlen(item->key);
            siz += strlen(item->value);
            siz += 4; //': ' and '\r\n'
        }
        idx++;

        if (siz + 1 > *buffer_len - 2)
        {
            // if this item would not fit to the buffer, return the index of the last fitting one
            ret_idx = idx - 1;
            ESP_LOGE(TAG, "Buffer length is small to fit all the headers");
            break;
        }
    }

    if (siz == 0)
    {
        return 0;
    }
    if (ret_idx < 0)
    {
        // all items would fit, mark this as the end of http header string
        ret_idx = idx;
        is_end = true;
    }

    // iterate again over the header entries to write only the fitting indeces
    int str_len = 0;
    idx = 0;
    STAILQ_FOREACH(item, props, next)
    {
        if (item->value && idx >= index && idx < ret_idx)
        {
            str_len += snprintf(buffer + str_len, *buffer_len - str_len, "%s: %s\r\n", item->key, item->value);
        }
        idx++;
    }
    if (is_end)
    {
        // write the http header terminator if all header entries have been written in this function call
        str_len += snprintf(buffer + str_len, *buffer_len - str_len, "\r\n");
    }
    *buffer_len = str_len;
    return ret_idx;
}

esp_err_t properties_clean(properties_handle_t props)
{
    property_handle_t item = STAILQ_FIRST(props), tmp;
    while (item != NULL)
    {
        tmp = STAILQ_NEXT(item, next);
        free(item->key);
        free(item->value);
        free(item);
        item = tmp;
    }
    STAILQ_INIT(props);
    return ESP_OK;
}

size_t properties_count(properties_handle_t props)
{
    property_handle_t item;
    size_t count = 0;
    STAILQ_FOREACH(item, props, next)
    {
        count++;
    }
    return count;
}

int properties_is_empty(properties_handle_t props)
{
    return STAILQ_EMPTY(props);
}

property_handle_t properties_get_next(properties_handle_t props, property_handle_t cur)
{
    if (cur == NULL)
    {
        return STAILQ_FIRST(props);
    }

    return STAILQ_NEXT(cur, next);
}