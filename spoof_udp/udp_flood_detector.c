// udp_flood_detector.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>

#define FLOOD_THRESHOLD 50  // Lowered for testing
#define MAX_SOURCES 1000
#define INTERFACE "enp0s1"
struct SourceStats {
    struct in_addr src_ip;
    int packet_count;
    time_t last_reset;
};

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL *connect_to_server(SSL_CTX *ctx) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8555);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ssl;
}

int find_or_create_source(struct SourceStats stats[], int *count, struct in_addr ip) {
    for (int i = 0; i < *count; i++) {
        if (stats[i].src_ip.s_addr == ip.s_addr) return i;
    }

    if (*count < MAX_SOURCES) {
        stats[*count].src_ip = ip;
        stats[*count].packet_count = 0;
        stats[*count].last_reset = time(NULL);
        return (*count)++;
    }

    return -1; // Too many sources
}

int main() {
    initialize_openssl();
    SSL_CTX *ctx = create_ssl_context();
    SSL *ssl = connect_to_server(ctx);

    printf("Starting UDP flood detector...\n");

    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (raw_sock < 0) {
        perror("Packet socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind to specific interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = if_nametoindex(INTERFACE);
    if (sll.sll_ifindex == 0) {
        perror("Interface not found. Check interface name.");
        exit(EXIT_FAILURE);
    }
    if (bind(raw_sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Bind to interface failed");
        exit(EXIT_FAILURE);
    }

    struct SourceStats sources[MAX_SOURCES];
    int src_count = 0;

    while (1) {
        unsigned char buffer[65536];
        int data_size = recvfrom(raw_sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            perror("recvfrom failed");
            continue;
        }

        // Skip Ethernet header (14 bytes)
        struct iphdr *ip_header = (struct iphdr*)(buffer + 14);
        if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr*)(buffer + 14 + ip_header->ihl * 4);
            struct in_addr src_ip;
            src_ip.s_addr = ip_header->saddr;

            int idx = find_or_create_source(sources, &src_count, src_ip);
            if (idx >= 0) {
                time_t now = time(NULL);
                if (now - sources[idx].last_reset > 1) {
                    sources[idx].packet_count = 0;
                    sources[idx].last_reset = now;
                }

                sources[idx].packet_count++;
                printf("Current count from %s: %d (since %ld seconds ago)\n",
       inet_ntoa(src_ip), sources[idx].packet_count, now - sources[idx].last_reset);

                printf("Got UDP packet from %s to port %d | Count: %d\n",
                       inet_ntoa(src_ip), ntohs(udp_header->dest), sources[idx].packet_count);

                if (sources[idx].packet_count > FLOOD_THRESHOLD) {
                    char alert[256];
                    snprintf(alert, sizeof(alert), "[ALERT] UDP flood detected from %s\n", inet_ntoa(src_ip));
                    printf("%s", alert);
                    int sent = SSL_write(ssl, alert, strlen(alert));
                    if (sent <= 0) {
                        printf("SSL_write failed\n");
                    }
                    sources[idx].packet_count = 0;
                }
            }
        }
    }

    // Cleanup (not reachable)
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(raw_sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
