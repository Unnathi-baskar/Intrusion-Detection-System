#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <net/route.h>

#define BUFFER_SIZE 65536
#define MAX_KNOWN_NETWORKS 500
#define TTL_THRESHOLD 10
#define DEBUG 1

typedef struct {
    struct in_addr network;
    struct in_addr mask;
    int expected_ttl;
    int is_whitelisted;
} KnownNetwork;

KnownNetwork known_networks[MAX_KNOWN_NETWORKS];
int known_network_count = 0;
SSL_CTX *ssl_ctx;
SSL *ssl;
int ssl_socket;

void init_ssl_client();
int connect_to_server(const char *server_ip, int port);
void send_alert(const char *message);
void add_known_network(const char *cidr, int ttl, int whitelisted);
int is_whitelisted(const char *ip);
int get_expected_ttl(const char *ip);
void initialize_known_networks();
int is_spoofed_packet(const char *source_ip, int ttl, uint16_t ip_id);
void print_packet_info(struct iphdr *ip_header);
void process_packet(unsigned char *buffer, int size);

void init_ssl_client() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ssl_ctx);
}

int connect_to_server(const char *server_ip, int port) {
    struct sockaddr_in addr;
    
    ssl_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (ssl_socket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);

    if (connect(ssl_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        close(ssl_socket);
        return 0;
    }

    SSL_set_fd(ssl, ssl_socket);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}

void send_alert(const char *message) {
    if (SSL_write(ssl, message, strlen(message)) <= 0) {
        ERR_print_errors_fp(stderr);
    }
}

void add_known_network(const char *cidr, int ttl, int whitelisted) {
    if (known_network_count >= MAX_KNOWN_NETWORKS) return;

    char *slash = strchr(cidr, '/');
    if (!slash) return;

    char ip_str[16];
    strncpy(ip_str, cidr, slash - cidr);
    ip_str[slash - cidr] = '\0';
    
    int mask_bits = atoi(slash + 1);
    struct in_addr network, mask;
    
    inet_pton(AF_INET, ip_str, &network);
    mask.s_addr = htonl(~((1 << (32 - mask_bits)) - 1));
    
    known_networks[known_network_count].network = network;
    known_networks[known_network_count].mask = mask;
    known_networks[known_network_count].expected_ttl = ttl;
    known_networks[known_network_count].is_whitelisted = whitelisted;
    known_network_count++;
}

int is_whitelisted(const char *ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);

    for (int i = 0; i < known_network_count; i++) {
        if ((addr.s_addr & known_networks[i].mask.s_addr) == 
            (known_networks[i].network.s_addr & known_networks[i].mask.s_addr)) {
            return known_networks[i].is_whitelisted;
        }
    }
    return 0;
}

int get_expected_ttl(const char *ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);

    for (int i = 0; i < known_network_count; i++) {
        if ((addr.s_addr & known_networks[i].mask.s_addr) == 
            (known_networks[i].network.s_addr & known_networks[i].mask.s_addr)) {
            return known_networks[i].expected_ttl;
        }
    }
    return 64; // Default TTL
}

void initialize_known_networks() {
    add_known_network("142.250.0.0/16", 120, 1);
    add_known_network("172.217.0.0/16", 120, 1);
    add_known_network("104.16.0.0/16", 120, 1);
    add_known_network("1.1.1.1/32", 120, 1);
    add_known_network("192.168.1.0/24", 64, 1);
    add_known_network("10.0.0.0/8", 64, 1);
    add_known_network("192.168.64.0/24", 128, 0);
}

int is_spoofed_packet(const char *source_ip, int ttl, uint16_t ip_id) {
    int expected_ttl = get_expected_ttl(source_ip);
    int ttl_diff = abs(ttl - expected_ttl);
    int spoof_detected = 0;
    
    if(ttl_diff > TTL_THRESHOLD) {
        if(DEBUG) printf("TTL anomaly detected: %d vs expected %d\n", ttl, expected_ttl);
        spoof_detected = 1;
    }
    
    if(ip_id == 0) {
        if(DEBUG) printf("Zero IP ID detected\n");
        spoof_detected = 1;
    }
    
    if(ip_id % 1000 == 0 && ttl_diff > 5) {
        if(DEBUG) printf("Suspicious IP ID pattern: %d\n", ip_id);
        spoof_detected = 1;
    }
    
    return spoof_detected;
}

void print_packet_info(struct iphdr *ip_header) {
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    struct sockaddr_in source, dest;
    
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;
    
    inet_ntop(AF_INET, &(source.sin_addr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dest.sin_addr), dest_ip, INET_ADDRSTRLEN);

    time_t now;
    time(&now);
    char timestamp[20];
    strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));

    printf("[%s] Packet: %s -> %s | TTL: %d | IP ID: %d | Size: %d bytes\n",
           timestamp, source_ip, dest_ip, 
           ip_header->ttl, ntohs(ip_header->id), ntohs(ip_header->tot_len));
}

void process_packet(unsigned char *buffer, int size) {
    struct iphdr *ip_header = (struct iphdr *)buffer;
    
    print_packet_info(ip_header);

    char source_ip[INET_ADDRSTRLEN];
    struct sockaddr_in source;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    inet_ntop(AF_INET, &(source.sin_addr), source_ip, INET_ADDRSTRLEN);

    if(DEBUG) {
        printf("Checking: %s | TTL: %d vs Expected: %d | IP ID: %d\n", 
               source_ip, ip_header->ttl, get_expected_ttl(source_ip), ntohs(ip_header->id));
    }

    if (strcmp(source_ip, "127.0.0.1") == 0 || is_whitelisted(source_ip)) {
        if(DEBUG) printf("Skipping whitelisted/localhost IP\n");
        return;
    }

    if (is_spoofed_packet(source_ip, ip_header->ttl, ntohs(ip_header->id))) {
        time_t now;
        time(&now);
        char timestamp[20];
        strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        char alert[512];
        snprintf(alert, sizeof(alert), 
                "[%s] SPOOFED PACKET! %s | TTL: %d (Expected: %d) | IP ID: %d",
                timestamp, source_ip, ip_header->ttl, 
                get_expected_ttl(source_ip), ntohs(ip_header->id));
        
        if(DEBUG) printf("Sending alert: %s\n", alert);
        send_alert(alert);
    }
}

int main() {
    int raw_socket;
    unsigned char buffer[BUFFER_SIZE];
    
    init_ssl_client();
    
    if (!connect_to_server("127.0.0.1", 8443)) {
        fprintf(stderr, "Failed to connect to SSL server\n");
        exit(EXIT_FAILURE);
    }

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("setsockopt failed");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }

    initialize_known_networks();
    
    printf("Starting IP spoofing detector...\n");

    while (1) {
        int packet_size = recv(raw_socket, buffer, BUFFER_SIZE, 0);
        if (packet_size < 0) {
            perror("Packet receive failed");
            continue;
        }
        
        process_packet(buffer, packet_size);
    }

    close(raw_socket);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(ssl_socket);
    
    return 0;
}

