//
// Created by Ivan Kishchenko on 22/1/25.
//
#include "ftp_pasv_session.h"
#include <esp_log.h>

void ftp_pasv_channel_inbound_read(channel_inbound_adapter_t *h, channel_handler_t c, const void *d, size_t s) {
    ESP_LOGI("ftp_p", "read: %d bytes", s);
}

esp_err_t ftp_pasv_channel_inbound_create(channel_inbound_handler_t *handler) {
    channel_inbound_adapter_t *self = malloc(sizeof(channel_inbound_adapter_t));
    if (!self) {
        return ESP_ERR_NO_MEM;
    }

    self->active = default_channel_inbound_active;
    self->read = ftp_pasv_channel_inbound_read;
    self->inactive = default_channel_inbound_inactive;
    self->destroy = default_channel_inbound_destroy;
    self->next = NULL;
    *handler = self;

    return ESP_OK;
}

void ftp_pasv_channel_outbound_write(channel_inbound_adapter_t *h, channel_handler_t c, const void *d, size_t s) {
    ESP_LOGI("ftp_p", "write: %d bytes", s);
}

esp_err_t ftp_pasv_channel_outbound_create(channel_outbound_handler_t *handler) {
    channel_outbound_adapter_t *self = malloc(sizeof(channel_outbound_adapter_t));
    if (!self) {
        return ESP_ERR_NO_MEM;
    }

    self->active = default_channel_outbound_active;
    self->write = ftp_pasv_channel_outbound_write;
    self->inactive = default_channel_outbound_inactive;
    self->destroy = default_channel_outbound_destroy;
    self->next = NULL;

    *handler = self;

    return ESP_OK;
}

channel_handler_t ftp_pasv_channel_create(channel_transport_handler_t transport) {
    channel_inbound_handler_t inbound = NULL;
    channel_outbound_handler_t outbound = NULL;

    channel_t *ch = malloc(sizeof(struct channel_t));

    if (ESP_OK != ftp_pasv_channel_inbound_create(&inbound)) {
        goto FAIL;
    }

    if (ESP_OK != ftp_pasv_channel_outbound_create(&outbound)) {
        goto FAIL;
    }

    ch->inbound = inbound;
    ch->outbound = outbound;
    ch->read = default_channel_read;
    ch->write = default_channel_write;
    ch->destroy = default_channel_destroy;

    ch->transport = transport;

    return ch;
FAIL:
    if (inbound) {
        inbound->destroy(inbound);
    }

    if (outbound) {
        outbound->destroy(outbound);
    }

    if (ch) {
        free(ch);
    }

    return NULL;
}
