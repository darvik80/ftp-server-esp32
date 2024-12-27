#include <stdio.h>
#include <esp_log.h>

#include "ftp_server.h"

void app_main(void)
{
    ESP_LOGI("ftp-server-esp32", "Starting ftp server");

    transport_handler_t handler;
    tcp_transport_create(&handler);
    tcp_transport_serve(handler, ftp_channel_create);
    tcp_transport_destroy(handler);
}
