FILE(GLOB_RECURSE sources
        ${CMAKE_SOURCE_DIR}/main/*.cpp
        ${CMAKE_SOURCE_DIR}/main/*.c
        ${CMAKE_SOURCE_DIR}/main/oss/*.c
)

idf_component_register(
        SRCS ${sources}
        INCLUDE_DIRS "."
        REQUIRES
        http_parser
        mbedtls
        esp_event
        nvs_flash
        esp_wifi
        tcp_transport
        wpa_supplicant
        core-esp32
        extra-services
)

spiffs_create_partition_image(storage ../data)
