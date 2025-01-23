//
// Created by Ivan Kishchenko on 12/12/24.
//
#include "transport.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <esp_log.h>

#define INVALID_SOCK (-1)

const char *TAG = "tcp";

void channel_inbound_active(channel_inbound_handler_t h, channel_handler_t c) {
    h->active(h, c);
}

void channel_inbound_read(channel_inbound_handler_t h, channel_handler_t c, const void* d, size_t s) {
    h->read(h, c, d, s);
}

void channel_inbound_inactive(channel_inbound_handler_t h, channel_handler_t c) {
    h->inactive(h, c);
}

void default_channel_inbound_active(channel_inbound_handler_t h, channel_handler_t c) {
    if (h->next) {
        h->next->active(h, c);
    }
}

void default_channel_inbound_inactive(channel_inbound_handler_t h, channel_handler_t c) {
    if (h->next) {
        h->next->inactive(h, c);
    }
}

void default_channel_inbound_destroy(channel_inbound_adapter_t *handler) {
    if (handler->next && handler->next->destroy) {
        handler->next->destroy(handler->next);
    }
    free(handler);
}

void channel_outbound_active(channel_outbound_handler_t h, channel_handler_t c) {
    h->active(h, c);
}

void channel_outbound_write(channel_outbound_handler_t h, channel_handler_t c, const void* d, size_t s) {
    h->write(h, c, d, s);
}

void channel_outbound_inactive(channel_outbound_handler_t h, channel_handler_t c) {
    h->inactive(h, c);
}

void default_channel_outbound_active(channel_outbound_handler_t h, channel_handler_t c) {
    if (h->next) {
        h->next->active(h, c);
    }
}

void default_channel_outbound_inactive(channel_outbound_handler_t h, channel_handler_t c) {
    if (h->next) {
        h->next->inactive(h, c);
    }
}

void default_channel_outbound_destroy(channel_outbound_adapter_t *handler) {
    if (handler->next && handler->next->destroy) {
        handler->next->destroy(handler->next);
    }
    free(handler);
}

void default_channel_read(channel_handler_t ch, void *d, size_t s) {
    ch->inbound->read(ch->inbound, ch, d, s);
}

void default_channel_write(channel_handler_t ch, const void *d, size_t s) {
    ch->transport->send(ch->transport, d, s);
}

void default_channel_destroy(channel_handler_t handler) {
    if (handler->inbound && handler->inbound->destroy) {
        handler->inbound->destroy(handler->inbound);
    }
    if (handler->outbound && handler->outbound->destroy) {
        handler->outbound->destroy(handler->outbound);
    }

    free(handler);
}

typedef struct tcp_client_transport_t {
    channel_transport_t base;
    channel_handler_t handler;

    int socket;
    StreamBufferHandle_t out_buf;

    uint8_t tx_buf[CONFIG_FTP_RECV_BUF_SIZE];
    uint16_t tx_buf_len;

} tcp_client_transport_t;

void tcp_client_transport_destroy(tcp_client_transport_t* transport) {
    close(transport->socket);
    vStreamBufferDelete(transport->out_buf);
    if (transport->handler && transport->handler->destroy) {
        transport->handler->destroy(transport->handler);
    }
    free(transport);
}

void tcp_client_transport_attach(tcp_client_transport_t *transport, channel_handler_t handler) {
    if (transport->handler && transport->handler->destroy) {
        transport->handler->destroy(transport->handler);
    }
    transport->handler = handler;
}

void tcp_client_transport_send(struct channel_transport_t *transport, const void* data, size_t len) {
    tcp_client_transport_t *self = __containerof(transport, tcp_client_transport_t, base);
    xStreamBufferSend(self->out_buf, data, len, portMAX_DELAY);
}

tcp_client_transport_t* tcp_client_transport_create(const int socket) {
    tcp_client_transport_t *transport = malloc(sizeof(struct tcp_client_transport_t));
    transport->socket = socket;
    transport->out_buf = xStreamBufferCreate(CONFIG_FTP_RECV_BUF_SIZE, 1);
    transport->tx_buf_len = 0;
    transport->handler = NULL;

    transport->base.send = tcp_client_transport_send;

    return transport;
}

typedef struct tcp_transport_t {
    int socket;
    int max_conn;
    tcp_client_transport_t** clients;
} tcp_transport_t;

esp_err_t errno2_esp_err(int err) {
    if (!err) {
        return ESP_OK;
    }
    switch (err) {
        case EACCES:
            return ESP_ERR_INVALID_ARG;

        case EAFNOSUPPORT:
            return ESP_ERR_INVALID_ARG;

        case EINVAL:
            return ESP_ERR_INVALID_ARG;

        case EMFILE:
            return ESP_FAIL;

        case ENOBUFS:
        case ENOMEM:
            return ESP_ERR_NO_MEM;
        default:
            return ESP_FAIL;
    }
}

esp_err_t tcp_transport_create(transport_handler_t *handler, int port, int max_conn) {
    esp_err_t err = ESP_OK;
    tcp_transport_t *transport = malloc(sizeof(tcp_transport_t));
    transport->max_conn = max_conn;
    transport->clients = malloc(sizeof(tcp_client_transport_t*) * max_conn);

    /* Server address */
    struct sockaddr_in server_address = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if ((transport->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        err = errno2_esp_err(errno);
        ESP_LOGE(TAG, "Could not create socket");
        goto FAIL;
    }

    const int enable = 1;
    if (setsockopt(transport->socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        ESP_LOGW(TAG, "setsockopt(SO_REUSEADDR) failed");
    }
    /* Bind socket to server address */
    if (bind(transport->socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        err = errno2_esp_err(errno);
        ESP_LOGE(TAG, "Cannot bind socket to address");
        goto FAIL;
    }

    // Set the server socket to non-blocking mode
    const int flags = fcntl(transport->socket, F_GETFL);
    if (fcntl(transport->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        err = errno2_esp_err(errno);
        ESP_LOGE(TAG, "Cannot set socket to O_NONBLOCK");
        goto FAIL;
    }

    for (int idx = 0; idx < max_conn; idx++) {
        transport->clients[idx] = NULL;
    }
    *handler = transport;
    if (listen(transport->socket, max_conn)) {
        err = errno2_esp_err(errno);
        ESP_LOGE(TAG, "Cannot listen on socket %d", transport->socket);
        goto FAIL;
    }

    return ESP_OK;

FAIL:
    close(transport->socket);
    free(transport);

    return err;
}

void tcp_transport_serve(transport_handler_t handler, channel_factory_t factory) {
    tcp_transport_t *transport = handler;

    struct sockaddr_in address;
    int addrlen = sizeof(address);

    uint8_t *rx_buf = malloc(CONFIG_FTP_RECV_BUF_SIZE);

    fd_set readfds;
    fd_set writefds;
    fd_set efds;
    FD_ZERO(&writefds);

    while (1) {
        // Find a free socket
        // Clear the socket set
        FD_ZERO(&readfds);
        FD_ZERO(&efds);
        // Add server socket to the set
        FD_SET(transport->socket, &readfds);
        FD_SET(transport->socket, &efds);

        int socket_idx = 0;
        int max_sd = transport->socket;
        for (socket_idx = 0; socket_idx < handler->max_conn; ++socket_idx) {
            tcp_client_transport_t* client = transport->clients[socket_idx];
            if (client == NULL) {
                break;
            }
            FD_SET(client->socket, &readfds);
            if (client->socket > max_sd) {
                max_sd = client->socket;
            }

            if (!client->tx_buf_len && !xStreamBufferIsEmpty(client->out_buf)) {
                client->tx_buf_len =
                        xStreamBufferReceive(client->out_buf, client->tx_buf, CONFIG_FTP_RECV_BUF_SIZE, 0);
                FD_SET(client->socket, &writefds);
            }
        }

        // Wait for activity on any socket
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        const int activity = select(max_sd + 1, &readfds, &writefds, &efds, &timeout);
        if (!activity) {
            continue;
        }
        if (activity < 0) {
            perror("select error");
            goto EXIT;
        }

        if (socket_idx != handler->max_conn) {
            // If server socket has activity, it's a new connection
            if (FD_ISSET(transport->socket, &readfds)) {
                int sock = accept(transport->socket, (struct sockaddr *) &address, (socklen_t *) &addrlen);
                if (sock < 0) {
                    perror("accept failed");
                    goto EXIT;
                }
                ESP_LOGI(TAG, "New connection, socket fd is %d", sock);
                int flags = fcntl(transport->socket, F_GETFL);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);
                tcp_client_transport_t *client =tcp_client_transport_create(sock);
                channel_handler_t client_handler = factory(&client->base);
                tcp_client_transport_attach(client, client_handler);
                transport->clients[socket_idx] = client;
                client_handler->inbound->active(client_handler->inbound, client_handler);
            }
        }

        for (int idx = 0; idx < handler->max_conn; ++idx)
        {
            if (transport->clients[idx] == NULL) {
                continue;
            }

            tcp_client_transport_t* client = transport->clients[idx];

            // receive data
            if (FD_ISSET(client->socket, &readfds)) {
                ssize_t size = recv(client->socket, rx_buf, CONFIG_FTP_RECV_BUF_SIZE, 0);
                if (size > 0) {
                    ESP_LOGI(TAG, "%d Received %zu bytes", client->socket, size);
                    client->handler->inbound->read(client->handler->inbound, client->handler, rx_buf, size);
                } else if (!size) {
                    ESP_LOGI(TAG, "%d Client disconnected", client->socket);
                    printf("conn closed");
                    tcp_client_transport_destroy(client);
                    transport->clients[idx] = NULL;
                } else {
                    int err = errno;
                    ESP_LOGI(TAG, "%d Client disconnected, err: %d", client->socket, err);
                    tcp_client_transport_destroy(client);
                    transport->clients[idx] = NULL;
                }
            }
        }

        for (int idx = 0; idx < handler->max_conn; ++idx) {
            if (transport->clients[idx] == NULL) {
                continue;
            }

            tcp_client_transport_t* client = transport->clients[idx];
            if (FD_ISSET(client->socket, &writefds)) {
                if (client->tx_buf_len > 0) {
                    const ssize_t size = send(client->socket, client->tx_buf, client->tx_buf_len, 0);
                    if (size > 0) {
                        ESP_LOGI(TAG, "%d Sent %zu bytes", client->socket, size);
                        memmove(client->tx_buf, client->tx_buf + size, client->tx_buf_len - size);
                        client->tx_buf_len -= size;
                        if (client->tx_buf_len > 0) {
                            FD_SET(client->socket, &writefds);
                        }
                    } else {
                        ESP_LOGI(TAG, "%d Client disconnected", client->socket);
                        tcp_client_transport_destroy(client);
                        transport->clients[idx] = NULL;
                    }
                }
            }
            if (FD_ISSET(client->socket, &efds)) {
                tcp_client_transport_destroy(client);
                transport->clients[idx] = NULL;
            }
        }
    }

EXIT:
    for (int idx = 0; idx < handler->max_conn; ++idx) {
        if (transport->clients[idx] != NULL) {
            tcp_client_transport_destroy(transport->clients[idx]);
        }
    }
    free(rx_buf);
}

int tcp_transport_get_port(transport_handler_t handler) {
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(handler->socket, (struct sockaddr *)&sin, &len) == -1) {
        return -1;
    }

    return ntohs(sin.sin_port);
}

void tcp_transport_destroy(transport_handler_t handler) {
    for (int idx = 0; idx < handler->max_conn; ++idx) {
        if (handler->clients[idx] != NULL) {
            tcp_client_transport_destroy(handler->clients[idx]);
        }
    }
    free(handler->clients);
    free(handler);
}
