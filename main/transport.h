//
// Created by Ivan Kishchenko on 12/12/24.
//

# pragma once

#include <freertos/FreeRTOS.h>
#include <esp_err.h>

typedef struct channel_transport_t {
    void (*send)(struct channel_transport_t*, const void* data, size_t);
} channel_transport_t;

typedef channel_transport_t* channel_transport_handler_t;

typedef struct channel_t {
    void (*read)(struct channel_t*, void*, size_t);
    void (*write)(struct channel_t*, const void*, size_t);
    void (*destroy)(struct channel_t*);

    struct channel_inbound_adapter_t* inbound;
    struct channel_outbound_adapter_t* outbound;

    channel_transport_handler_t transport;
} channel_t;

typedef channel_t* channel_handler_t;

typedef struct channel_inbound_adapter_t {
    struct channel_inbound_adapter_t* next;

    void (*active)(struct channel_inbound_adapter_t*, channel_handler_t);
    void (*read)(struct channel_inbound_adapter_t*, channel_handler_t, const void*, size_t);
    void (*inactive)(struct channel_inbound_adapter_t*, channel_handler_t);
    void(*destroy)(struct channel_inbound_adapter_t*);
} channel_inbound_adapter_t;

typedef channel_inbound_adapter_t* channel_inbound_handler_t;

typedef struct channel_outbound_adapter_t {
    struct channel_outbound_adapter_t* next;

    void (*active)(struct channel_outbound_adapter_t*, channel_handler_t);
    void (*write)(struct channel_outbound_adapter_t*, channel_handler_t, const void*, size_t);
    void (*inactive)(struct channel_outbound_adapter_t*, channel_handler_t);
    void(*destroy)(struct channel_outbound_adapter_t*);
} channel_outbound_adapter_t;

typedef channel_outbound_adapter_t* channel_outbound_handler_t;

void channel_inbound_active(channel_inbound_handler_t h, channel_handler_t c);

void channel_inbound_read(channel_inbound_handler_t h, channel_handler_t c, const void* d, size_t s);

void channel_inbound_inactive(channel_inbound_handler_t h, channel_handler_t c);

void default_channel_inbound_active(channel_inbound_handler_t h, channel_handler_t c);

void default_channel_inbound_inactive(channel_inbound_handler_t h, channel_handler_t c);

void channel_outbound_active(channel_outbound_handler_t h, channel_handler_t c);

void channel_outbound_write(channel_outbound_handler_t h, channel_handler_t c, const void* d, size_t s);

void channel_outbound_inactive(channel_outbound_handler_t h, channel_handler_t c);

void default_channel_outbound_active(channel_outbound_handler_t h, channel_handler_t c);

void default_channel_outbound_inactive(channel_outbound_handler_t h, channel_handler_t c);

/*
 * create tcp transport
*/
typedef struct tcp_transport_t* transport_handler_t;

typedef channel_handler_t (*channel_factory_t)(channel_transport_handler_t);

esp_err_t tcp_transport_create(transport_handler_t *handler);

void tcp_transport_serve(transport_handler_t handler, channel_factory_t factory);

void tcp_transport_destroy(transport_handler_t handler);
