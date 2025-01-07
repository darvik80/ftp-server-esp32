//
// Created by Ivan Kishchenko on 12/12/24.
//

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "transport.h"

channel_handler_t ftp_channel_create(channel_transport_handler_t transport);

void ftp_channel_read(channel_handler_t ch, void* d, size_t s);

void ftp_channel_write(channel_handler_t ch, const void* d, size_t s);

void ftp_channel_destroy(channel_handler_t handler);

#ifdef __cplusplus
}
#endif
