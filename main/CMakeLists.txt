FILE(GLOB_RECURSE sources
        ${CMAKE_SOURCE_DIR}/main/*.c
        ${CMAKE_SOURCE_DIR}/main/http/*.c
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
)
