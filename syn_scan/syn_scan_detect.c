#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define DEFAULT_PORT 3009
#define MAX_LOGS     1024
#define MAX_LINE     128

static char *iface, *target_ip, *cert_file, *key_file;
static uint32_t target_addr;
static pcap_t *pcap_handle;
static SSL_CTX *ssl_ctx;
static int listen_fd = -1, client_fd = -1;
static SSL *ssl = NULL;

static char *logs[MAX_LOGS];
static int log_start = 0, log_count = 0;

void cleanup(int sig) {
    if (ssl) SSL_free(ssl);
    if (client_fd >= 0) close(client_fd);
    if (listen_fd >= 0) close(listen_fd);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    if (pcap_handle) pcap_close(pcap_handle);
    for (int i = 0; i < log_count; i++) free(logs[(log_start + i) % MAX_LOGS]);
    printf("\nShutting down.\n");
    exit(0);
}

void add_log(const char *line) {
    printf("%s\n", line);
    fflush(stdout);

    char *copy = strdup(line);
    if (!copy) return;

    if (log_count < MAX_LOGS) {
        logs[(log_start + log_count) % MAX_LOGS] = copy;
        log_count++;
    } else {
        free(logs[log_start]);
        logs[log_start] = copy;
        log_start = (log_start + 1) % MAX_LOGS;
    }
    if (ssl) {
        SSL_write(ssl, copy, strlen(copy));
        SSL_write(ssl, "\n", 1);
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct ip  *ip_hdr = (struct ip*)(bytes + 14);
    if (ip_hdr->ip_p != IPPROTO_TCP) return;
    struct tcphdr *tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + (ip_hdr->ip_hl * 4));
    if (!(tcp_hdr->th_flags & TH_SYN) || (tcp_hdr->th_flags & TH_ACK)) return;
    if (ip_hdr->ip_dst.s_addr != target_addr) return;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN], line[MAX_LINE];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst, sizeof(dst));
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%F %T", tm);

    snprintf(line, sizeof(line),
             "[%s] SYN: %s:%d → %s:%d",
             ts,
             src, ntohs(tcp_hdr->th_sport),
             dst, ntohs(tcp_hdr->th_dport));

    add_log(line);
}

void init_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE], filter_exp[128];
    bpf_u_int32 net, mask;

    if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) net = mask = 0;
    pcap_handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle) { perror("pcap_open_live"); exit(1); }

    snprintf(filter_exp, sizeof(filter_exp),
             "tcp[tcpflags] & tcp-syn != 0 "
             "and tcp[tcpflags] & tcp-ack == 0 "
             "and dst host %s", target_ip);

    struct bpf_program fp;
    pcap_compile(pcap_handle, &fp, filter_exp, 1, net);
    pcap_setfilter(pcap_handle, &fp);
}

void init_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) { ERR_print_errors_fp(stderr); exit(1); }
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

void init_listener(int port) {
    struct sockaddr_in addr;
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1; setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr))<0 ||
        listen(listen_fd, 1)<0) {
        perror("bind/listen"); exit(1);
    }
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);
}

int main() {
    iface     = "ens160";
    target_ip = "172.20.10.3";
    cert_file = "syn_detect.crt";
    key_file  = "syn_detect.key";
    int port  = 3009;

    if (!inet_pton(AF_INET, target_ip, &target_addr)) {
        fprintf(stderr, "Invalid IP: %s\n", target_ip);
        exit(1);
    }

    signal(SIGINT, cleanup);
    init_pcap();
    init_ssl();
    init_listener(port);

    printf("Listening for SYN→%s on %s\n", target_ip, iface);
    printf("TLS server ready on port %d (cert=%s, key=%s)\n\n", port, cert_file, key_file);

    while (1) {
        if (client_fd < 0) {
            client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd >= 0) {
                ssl = SSL_new(ssl_ctx);
                SSL_set_fd(ssl, client_fd);
                if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl); ssl = NULL;
                    close(client_fd); client_fd = -1;
                } else {
                    for (int i = 0; i < log_count; i++) {
                        char *ln = logs[(log_start + i) % MAX_LOGS];
                        SSL_write(ssl, ln, strlen(ln));
                        SSL_write(ssl, "\n", 1);
                    }
                    printf("\u2192 TLS client connected; streaming logs\n");
                }
            }
        }

        pcap_dispatch(pcap_handle, 1, packet_handler, NULL);

        if (ssl && SSL_get_shutdown(ssl) & (SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN)) {
            SSL_free(ssl); ssl = NULL;
            close(client_fd); client_fd = -1;
            printf("\u2192 TLS client disconnected\n");
        }
    }

    return 0;
}
