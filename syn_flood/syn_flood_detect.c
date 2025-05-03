#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define TARGET_IP "172.20.10.3"
#define SSL_PORT 4443

SSL *ssl;
SSL_CTX *ctx;

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("SSL_CTX_new failed");
        exit(EXIT_FAILURE);
    }
}

void connect_ssl() {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SSL_PORT);
    inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void log_ssl(const char *message) {
    if (ssl) {
        SSL_write(ssl, message, strlen(message));
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14);  // Ethernet header is 14 bytes
    if (iph->ip_p != IPPROTO_TCP) return;

    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + (iph->ip_hl * 4));
    if (tcph->syn && !tcph->ack) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "SYN detected from %s to %s:%d\n",
                 inet_ntoa(iph->ip_src),
                 inet_ntoa(iph->ip_dst),
                 ntohs(tcph->dest));
        printf("%s", log_msg);
        log_ssl(log_msg);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[100];
    bpf_u_int32 net;

    snprintf(filter_exp, sizeof(filter_exp), "tcp[tcpflags] & tcp-syn != 0 and dst host %s", TARGET_IP);

    handle = pcap_open_live("ens160", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    init_openssl();
    connect_ssl();

    printf("Listening for SYN packets on ens160...\n");
    pcap_loop(handle, -1, packet_handler, NULL);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    pcap_close(handle);

    return 0;
}