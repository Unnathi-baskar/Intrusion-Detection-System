#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 8555
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 10
#define LOG_FILE "alerts.log"

volatile sig_atomic_t stop_flag = 0;

void handle_signal(int sig) {
    stop_flag = 1;
}

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    return ctx;
}

void configure_context(SSL_CTX *ctx) {    
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(EXIT_FAILURE);
    }
}

void log_spoofing_alert(const char *message) {
    time_t now = time(NULL);
    char timestamp[30];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    printf("\033[1;31m[%s] %s\033[0m\n", timestamp, message);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fclose(log_file);
    }
}

void log_connection_details(const char *client_ip, int client_port) {
    time_t now = time(NULL);
    char timestamp[30];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "[%s] Connection from: %s:%d\n", 
               timestamp, client_ip, client_port);
        fclose(log_file);
    }
}

void handle_client(SSL *ssl, const char *client_ip, int client_port) {
    char buffer[BUFFER_SIZE];
    int bytes;
    
    log_connection_details(client_ip, client_port);
    printf("Handling client %s:%d\n", client_ip, client_port);
    
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        buffer[bytes] = '\0';
        log_spoofing_alert(buffer);
        
        char ack[100];
        unsigned short checksum = 0;
        for(int i=0; i<bytes; i++) checksum += buffer[i];
        
        snprintf(ack, sizeof(ack), "ACK: %d bytes | Checksum: %04X", bytes, checksum);
        if (SSL_write(ssl, ack, strlen(ack)) <= 0) {
            printf("Failed to send acknowledgement\n");
            break;
        }
    }
    
    if (bytes <= 0) {
        int err = SSL_get_error(ssl, bytes);
        if (err != SSL_ERROR_ZERO_RETURN) {
            printf("SSL error with client %s:%d: %d\n", client_ip, client_port, err);
            ERR_print_errors_fp(stderr);
        }
    }
    
    printf("Closing connection with %s:%d\n", client_ip, client_port);
}

int main() {
    int sockfd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    SSL_CTX *ctx;
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    init_openssl();
    ctx = create_context();
    configure_context(ctx);
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Setsockopt failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    printf("SSL Server listening on port %d...\n", PORT);
    printf("Logging alerts to: %s\n", LOG_FILE);
    
    while (!stop_flag) {
        SSL *ssl;
        char client_ip[INET_ADDRSTRLEN];
        int client_port;
        
        client_len = sizeof(client_addr);
        if ((client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
            if (!stop_flag) perror("Accept failed");
            continue;
        }
        
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(client_addr.sin_port);
        
        printf("Accepted connection from %s:%d\n", client_ip, client_port);
        
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "SSL handshake failed with %s:%d\n", client_ip, client_port);
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        
        printf("SSL connection established with %s:%d using %s\n", 
               client_ip, client_port, SSL_get_cipher(ssl));
        
        handle_client(ssl, client_ip, client_port);
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    
    printf("\nShutting down server...\n");
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    return 0;
}
