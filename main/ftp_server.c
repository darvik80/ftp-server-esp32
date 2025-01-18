//
// Created by Ivan Kishchenko on 12/12/24.
//
#include "ftp_server.h"
#include <esp_log.h>
#include <string.h>
#include <transport.h>
#include <unistd.h>

/**
 *
 * ftp inbound command handler
 *
 */

void ftp_channel_inbound_command_active(channel_inbound_adapter_t *h, channel_handler_t c) {
    const char *message = "220 ESP32 FTP Server";
    c->outbound->write(c->outbound, c, message, strlen(message));
}

void ftp_channel_inbound_command_read(channel_inbound_adapter_t *h, channel_handler_t c, const void *d, size_t s) {
    ESP_LOGI("ftp", "CMD: %s", (char*)d);
    const char *message = "220 OK";
    c->outbound->write(c->outbound, c, message, strlen(message));
}

void ftp_channel_inbound_command_destroy(channel_inbound_adapter_t *handler) {
    if (handler->next && handler->next->destroy) {
        handler->next->destroy(handler->next);
    }
    free(handler);
}

esp_err_t ftp_channel_inbound_command_create(channel_inbound_handler_t *handler) {
    channel_inbound_adapter_t *self = malloc(sizeof(channel_inbound_adapter_t));
    if (!self) {
        return ESP_ERR_NO_MEM;
    }

    self->active = ftp_channel_inbound_command_active;
    self->read = ftp_channel_inbound_command_read;
    self->inactive = default_channel_inbound_inactive;
    self->destroy = ftp_channel_inbound_command_destroy;
    self->next = NULL;
    *handler = self;

    return ESP_OK;
}

/**
 *
 * ftp inbound line based handler
 *
 */
typedef struct {
    channel_inbound_adapter_t base;
    char data[1024];
    size_t size;
} ftp_channel_inbound_line_based_t;

void ftp_channel_inbound_line_based_read(channel_inbound_handler_t h, channel_handler_t c, const void *d, size_t s) {
    ftp_channel_inbound_line_based_t *self = __containerof(h, ftp_channel_inbound_line_based_t, base);

    // truncate
    size_t capacity = sizeof(self->data);
    if (capacity < s) {
        memcpy(self->data, d + s - capacity, capacity);
        self->size = capacity;
    } else {
        if (capacity - self->size < s) {
            const size_t truncated_size = self->size + s - capacity;
            memmove(self->data, self->data + truncated_size, capacity - truncated_size);
            self->size -= truncated_size;
        }
        memcpy(self->data + self->size, d, s);
        self->size += s;
    }

    char *ptr = strnstr(self->data, "\r\n", self->size);
    if (ptr != NULL && self->base.next) {
        *ptr = 0;
        size_t len = ptr - self->data;
        self->base.next->read(h, c, self->data, len);
        len += 2, ptr += 2;
        memmove(self->data, ptr, self->size - len);
        self->size -= len;
    }
}

void ftp_channel_inbound_line_based_destroy(channel_inbound_handler_t ch) {
    ftp_channel_inbound_line_based_t *self = __containerof(ch, ftp_channel_inbound_line_based_t, base);
    if (ch->next && ch->next->destroy) {
        ch->next->destroy(ch->next);
    }
    free(self);
}

esp_err_t ftp_channel_inbound_line_based_create(channel_inbound_handler_t next, channel_inbound_handler_t *handler) {
    ftp_channel_inbound_line_based_t *ch = malloc(sizeof(ftp_channel_inbound_line_based_t));
    if (!ch) {
        return ESP_ERR_NO_MEM;
    }
    bzero(ch, sizeof(ftp_channel_inbound_line_based_t));
    ch->size = 0;

    ch->base.active = default_channel_inbound_active;
    ch->base.read = ftp_channel_inbound_line_based_read;
    ch->base.inactive = default_channel_inbound_inactive;
    ch->base.destroy = ftp_channel_inbound_line_based_destroy;
    ch->base.next = next;

    *handler = &ch->base;

    return ESP_OK;
}

/**
 *
 * ftp outbound handler
 *
 */

typedef struct ftp_channel_outbound_t {
    channel_outbound_adapter_t base;
} ftp_channel_outbound_t;

void ftp_channel_outbound_destroy(channel_outbound_handler_t h) {
    ftp_channel_outbound_t *self = __containerof(h, ftp_channel_outbound_t, base);

    if (self->base.next && self->base.next->destroy) {
        self->base.next->destroy(self->base.next);
    }

    free(self);
}

void ftp_channel_outbound_write(channel_outbound_handler_t, channel_handler_t ch, const void *d, size_t s) {
    ch->write(ch, d, s);
    ch->write(ch, "\r\n", 2);
}

channel_outbound_handler_t ftp_channel_outbound_create() {
    ftp_channel_outbound_t *ch = malloc(sizeof(ftp_channel_outbound_t));
    bzero(ch, sizeof(ftp_channel_outbound_t));

    ch->base.active = default_channel_outbound_active;
    ch->base.write = ftp_channel_outbound_write;
    ch->base.inactive = default_channel_outbound_inactive;
    ch->base.destroy = ftp_channel_outbound_destroy;
    ch->base.next = NULL;

    return &ch->base;
}

/**
 *
 * ftp channel
 *
 */

void ftp_channel_read(channel_handler_t ch, void *d, size_t s) {
    ch->inbound->read(ch->inbound, ch, d, s);
}

void ftp_channel_write(channel_handler_t ch, const void *d, size_t s) {
    ch->transport->send(ch->transport, d, s);
}

void ftp_channel_destroy(channel_handler_t handler) {
    if (handler->inbound && handler->inbound->destroy) {
        handler->inbound->destroy(handler->inbound);
    }
    if (handler->outbound && handler->outbound->destroy) {
        handler->outbound->destroy(handler->outbound);
    }

    free(handler);
}

channel_handler_t ftp_channel_create(channel_transport_handler_t transport) {
    channel_inbound_handler_t command_handler = NULL, line_handler = NULL;

    channel_t *ch = malloc(sizeof(struct channel_t));
    if (!ch) {
        goto FAIL;
    }

    if (ESP_OK != ftp_channel_inbound_command_create(&command_handler)) {
        goto FAIL;
    }
    if (ESP_OK != ftp_channel_inbound_line_based_create(command_handler, &line_handler)) {
        command_handler->destroy(command_handler);
        goto FAIL;
    }

    ch->inbound = line_handler;
    ch->outbound = ftp_channel_outbound_create();
    ch->read = ftp_channel_read;
    ch->write = ftp_channel_write;
    ch->destroy = ftp_channel_destroy;

    ch->transport = transport;

    return ch;

FAIL:
    if (command_handler && command_handler->destroy) {
        command_handler->destroy(command_handler);
    }
    if (line_handler && line_handler->destroy) {
        line_handler->destroy(line_handler);
    }
    return NULL;
}
