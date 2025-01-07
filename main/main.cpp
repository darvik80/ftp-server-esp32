#include "ftp_server.h"

#include <core/Application.h>
#include <core/system/SystemEvent.h>
#include <core/system/telemetry/TelemetryService.h>
#include <core/system/wifi/WifiService.h>
#include <core/system/mqtt/MqttService.h>
#include <sntp/SNTPService.h>

#include <oss/oss_auth.h>
#include <oss/oss_client.h>
#include <oss/properties.h>

#include <cstdio>
#include <esp_http_client.h>
#include <esp_log.h>

#include "oss_config.h"

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048

enum UserMessage
{
    User_ConfigMsg,
};

struct ConfigMessage : CMessage<User_ConfigMsg, Sys_User>
{
    std::string config;
};


[[maybe_unused]] void fromJson(const cJSON* json, ConfigMessage& event)
{
    cJSON* item = json->child;
    while (item)
    {
        if (!strcmp(item->string, "config") && item->type == cJSON_String)
        {
            event.config = item->valuestring;
        }

        item = item->next;
    }
}

class FtpServer : public Application<FtpServer>,
                  public TMessageSubscriber<FtpServer, SystemEventChanged, SNTPSetupMessage, ConfigMessage>
{
public:
    FtpServer() = default;

    static esp_err_t callback(esp_http_client_event_t *evt)
    {
        if (evt->event_id == HTTP_EVENT_ON_DATA)
        {
            esp_logi(ftp, "data: %d", evt->data_len);
        }

        return ESP_OK;
    }

    void handle(const SNTPSetupMessage& event)
    {
        FreeRTOSTask::execute([]
        {
            oss_config_t oss_config{
                .endpoint = OSS_BUCKET ".oss-" OSS_REGION ".aliyuncs.com",
                .access_key_id = OSS_ACCESS_KEY,
                .access_key_secret = OSS_SECRET_TOCKEN,
                .region = OSS_REGION,
                .bucket = OSS_BUCKET,
            };

            oss_client_handler_t handler;
            oss_client_create(&oss_config, &handler);
            oss_client_get(handler, "0000003f01394261876aca024cae0ba8_0041cd580320455e90a9427891fc5124.jpg", callback);
            oss_client_get(handler, "0000003f01394261876aca024cae0ba8_0041cd580320455e90a9427891fc5124.jpg", callback);
            oss_client_get(handler, "0041cd580320455e90a9427891fc5124.jpg", callback);
            oss_client_destroy(handler);
        }, "oss", 4096);
    }

    void handle(const SystemEventChanged& event)
    {
        if (event.status == SystemStatus::Wifi_Connected)
        {
            FreeRTOSTask::execute([]
            {
                transport_handler_t handler;
                tcp_transport_create(&handler);
                tcp_transport_serve(handler, ftp_channel_create);
                tcp_transport_destroy(handler);
            }, "ftp_server", 4096);
        }
    }

    void handle(const ConfigMessage& event)
    {
        esp_logi(app, "new config: %s", event.config.c_str());
    }

protected:
    void userSetup() override
    {
        getRegistry().getEventBus().subscribe(shared_from_this());
        getRegistry().create<WifiService>();
        auto& mqtt = getRegistry().create<MqttService>();
        getRegistry().create<TelemetryService>();
        getRegistry().create<SNTPService>();

        mqtt.addJsonHandler<ConfigMessage>("/sys/config", MQTT_SUB_RELATIVE);
        mqtt.addJsonHandler<ConfigMessage>("/sys/test", MQTT_SUB_ABSOLUTE);
        mqtt.addJsonProcessor<Telemetry>("/sys/telemetry");
    }
};

static std::shared_ptr<FtpServer> app;

extern "C" void app_main(void)
{
    esp_logi(ftp, "Starting ftp server");

    app = std::make_shared<FtpServer>();
    app->setup();

    // transport_handler_t handler;
    // tcp_transport_create(&handler);
    // tcp_transport_serve(handler, ftp_channel_create);
    // tcp_transport_destroy(handler);
}
