#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <zlib.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define BUFFER_SIZE 8192
#define MAX_THREADS 10
#define DEFAULT_PORT 8080
#define DEFAULT_ROOT "."
#define DEFAULT_MAX_BODY_SIZE 10485760
#define KEEP_ALIVE_TIMEOUT 5
#define REQUEST_TIMEOUT 30
#define MAX_REQUEST_SIZE 65536
#define SERVER_NAME "GrokHTTPServer/1.1"
#define MAX_PATH_LEN PATH_MAX
#define LOG_FILE "server.log"
#define AUTH_FILE "auth.txt"
#define CONFIG_FILE "config.ini"
#define MAX_HEADER_FIELD 1024
#define RATE_LIMIT_REQUESTS 10
#define RATE_LIMIT_WINDOW 60
volatile sig_atomic_t shutdown_flag = 0;
typedef struct {
    int port;
    char root_dir[PATH_MAX];
    size_t max_body_size;
} config_t;
typedef struct {
    int sockfd;
    struct sockaddr_in addr;
} client_t;
typedef struct {
    client_t **queue;
    int front, rear, count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} queue_t;
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int count;
    time_t last_reset;
} rate_limit_t;
typedef struct {
    char *username;
    char *password;
} auth_t;
queue_t *task_queue;
pthread_t threads[MAX_THREADS];
FILE *log_file;
unsigned char decoding_table[256];
const char *encoding_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
rate_limit_t rate_limits[256];
pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;
auth_t *auth_list = NULL;
int auth_count = 0;
void build_decoding_table() {
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)encoding_table[i]] = i;
    }
}
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
    if (input_length % 4 != 0) return NULL;
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
    unsigned char *decoded_data = malloc(*output_length + 1);
    if (decoded_data == NULL) return NULL;
    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        uint32_t sextet_b = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        uint32_t sextet_c = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        uint32_t sextet_d = data[i] == '=' ? 0 : decoding_table[(unsigned char)data[i]]; i++;
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }
    decoded_data[*output_length] = '\0';
    return decoded_data;
}
int load_auth_file() {
    FILE *file = fopen(AUTH_FILE, "r");
    if (!file) return 0;
    char line[256];
    auth_count = 0;
    while (fgets(line, sizeof(line), file)) {
        char *username = strtok(line, ":");
        char *password = strtok(NULL, "\n");
        if (username && password) {
            auth_list = realloc(auth_list, (auth_count + 1) * sizeof(auth_t));
            auth_list[auth_count].username = strdup(username);
            auth_list[auth_count].password = strdup(password);
            auth_count++;
        }
    }
    fclose(file);
    return auth_count > 0;
}
int load_config(config_t *config) {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) return 0;
    char line[256];
    config->port = DEFAULT_PORT;
    strncpy(config->root_dir, DEFAULT_ROOT, PATH_MAX);
    config->max_body_size = DEFAULT_MAX_BODY_SIZE;
    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");
        if (key && value) {
            while (*key && isspace(*key)) key++;
            while (*value && isspace(*value)) value++;
            char *end = value + strlen(value) - 1;
            while (end > value && isspace(*end)) *end-- = '\0';
            if (strcmp(key, "port") == 0) config->port = atoi(value);
            else if (strcmp(key, "root_dir") == 0) strncpy(config->root_dir, value, PATH_MAX - 1);
            else if (strcmp(key, "max_body_size") == 0) config->max_body_size = atol(value);
        }
    }
    fclose(file);
    return 1;
}
int authenticate(const char *headers) {
    char *auth = strstr(headers, "Authorization: Basic ");
    if (!auth) return 0;
    auth += 21;
    char *end = strchr(auth, '\r');
    if (end) *end = '\0';
    if (strlen(auth) > MAX_HEADER_FIELD) return 0;
    size_t len;
    unsigned char *decoded = base64_decode(auth, strlen(auth), &len);
    if (!decoded) return 0;
    char *colon = strchr((char *)decoded, ':');
    if (!colon) {
        free(decoded);
        return 0;
    }
    *colon = '\0';
    for (int i = 0; i < auth_count; i++) {
        if (strcmp((char *)decoded, auth_list[i].username) == 0 && strcmp(colon + 1, auth_list[i].password) == 0) {
            free(decoded);
            return 1;
        }
    }
    free(decoded);
    return 0;
}
int check_rate_limit(const char *ip) {
    pthread_mutex_lock(&rate_limit_mutex);
    time_t now = time(NULL);
    int found = -1;
    for (int i = 0; i < 256; i++) {
        if (rate_limits[i].ip[0] == '\0') {
            if (found == -1) found = i;
            continue;
        }
        if (strcmp(rate_limits[i].ip, ip) == 0) {
            if (now - rate_limits[i].last_reset >= RATE_LIMIT_WINDOW) {
                rate_limits[i].count = 0;
                rate_limits[i].last_reset = now;
            }
            rate_limits[i].count++;
            if (rate_limits[i].count > RATE_LIMIT_REQUESTS) {
                pthread_mutex_unlock(&rate_limit_mutex);
                return 0;
            }
            pthread_mutex_unlock(&rate_limit_mutex);
            return 1;
        }
    }
    if (found != -1) {
        strncpy(rate_limits[found].ip, ip, INET_ADDRSTRLEN);
        rate_limits[found].count = 1;
        rate_limits[found].last_reset = now;
        pthread_mutex_unlock(&rate_limit_mutex);
        return 1;
    }
    pthread_mutex_unlock(&rate_limit_mutex);
    return 0;
}
int gzip_compress(const char *data, size_t data_len, char **compressed, size_t *compressed_len) {
    z_stream strm = {0};
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    strm.next_in = (unsigned char *)data;
    strm.avail_in = data_len;
    *compressed_len = deflateBound(&strm, data_len);
    *compressed = malloc(*compressed_len);
    strm.next_out = (unsigned char *)*compressed;
    strm.avail_out = *compressed_len;
    if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&strm);
        free(*compressed);
        return -1;
    }
    *compressed_len = strm.total_out;
    deflateEnd(&strm);
    return 0;
}
int parse_range_header(const char *headers, off_t file_size, off_t *start, off_t *end) {
    char *range = strstr(headers, "Range: bytes=");
    if (!range) return 0;
    range += 13;
    char *dash = strchr(range, '-');
    if (!dash) return 0;
    *dash = '\0';
    *start = atoll(range);
    char *end_str = dash + 1;
    *end = end_str[0] ? atoll(end_str) : file_size - 1;
    if (*start >= file_size || *end >= file_size || *start > *end) return 0;
    return 1;
}
void *worker_thread(void *arg);
void enqueue(client_t *client);
client_t *dequeue();
void handle_client(int sockfd, struct sockaddr_in addr);
void send_response(int sockfd, int status, const char *content_type, const char *body, size_t body_len, int is_head, struct stat *st, int keep_alive, const char *etag, int use_gzip, const char *user_agent, off_t range_start, off_t range_end);
void send_file(int sockfd, const char *full_path, int status, int is_head, struct stat *st, int keep_alive, const char *etag, const char *user_agent, off_t range_start, off_t range_end);
void send_dir_listing(int sockfd, const char *full_path, const char *req_path, int keep_alive, const char *user_agent);
void parse_request(char *request, size_t bytes_read, char **method, char **path, char **query, char **headers, char **body, size_t *body_len, time_t *if_modified_since, char *etag, size_t etag_size, char *user_agent, size_t user_agent_size, int *keep_alive_timeout);
char *get_mime_type(const char *path);
void get_http_date(char *buf, size_t size);
void generate_etag(const char *path, struct stat *st, char *etag, size_t etag_size);
void log_message(int status, size_t bytes_sent, const char *format, ...);
int secure_path(const char *root_dir, const char *path, char *full_path, size_t full_path_size);
void signal_handler(int sig);
int compare_dirent(const void *a, const void *b);
int sanitize_query(char *query);
int main(int argc, char *argv[]) {
    config_t config;
    if (!load_config(&config)) {
        config.port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
        strncpy(config.root_dir, (argc > 2) ? argv[2] : DEFAULT_ROOT, PATH_MAX - 1);
        config.max_body_size = DEFAULT_MAX_BODY_SIZE;
    }
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        perror("Failed to open log file");
    }
    if (!load_auth_file()) {
        fprintf(stderr, "Warning: No valid auth credentials loaded\n");
    }
    build_decoding_table();
    memset(rate_limits, 0, sizeof(rate_limits));
    task_queue = malloc(sizeof(queue_t));
    task_queue->queue = malloc(sizeof(client_t *) * MAX_THREADS * 2);
    task_queue->front = task_queue->rear = task_queue->count = 0;
    pthread_mutex_init(&task_queue->mutex, NULL);
    pthread_cond_init(&task_queue->cond, NULL);
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config.port);
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    if (listen(server_sock, SOMAXCONN) < 0) {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    if (chdir(config.root_dir) < 0) {
        perror("chdir failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }
    log_message(0, 0, "Server listening on port %d, root: %s", config.port, config.root_dir);
    while (!shutdown_flag) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (!shutdown_flag) perror("Accept failed");
            continue;
        }
        setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
        client_t *client = malloc(sizeof(client_t));
        client->sockfd = client_sock;
        client->addr = client_addr;
        enqueue(client);
    }
    close(server_sock);
    for (int i = 0; i < MAX_THREADS; i++) {
        enqueue(NULL);
    }
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_mutex_destroy(&task_queue->mutex);
    pthread_cond_destroy(&task_queue->cond);
    free(task_queue->queue);
    free(task_queue);
    for (int i = 0; i < auth_count; i++) {
        free(auth_list[i].username);
        free(auth_list[i].password);
    }
    free(auth_list);
    pthread_mutex_destroy(&rate_limit_mutex);
    log_message(0, 0, "Server shutdown");
    if (log_file) fclose(log_file);
    return 0;
}
void *worker_thread(void *arg) {
    (void)arg;
    while (1) {
        client_t *client = dequeue();
        if (!client) break;
        handle_client(client->sockfd, client->addr);
        free(client);
    }
    return NULL;
}
void enqueue(client_t *client) {
    pthread_mutex_lock(&task_queue->mutex);
    task_queue->queue[task_queue->rear] = client;
    task_queue->rear = (task_queue->rear + 1) % (MAX_THREADS * 2);
    task_queue->count++;
    pthread_cond_signal(&task_queue->cond);
    pthread_mutex_unlock(&task_queue->mutex);
}
client_t *dequeue() {
    pthread_mutex_lock(&task_queue->mutex);
    while (task_queue->count == 0) {
        pthread_cond_wait(&task_queue->cond, &task_queue->mutex);
    }
    client_t *client = task_queue->queue[task_queue->front];
    client_t *result = client;
    task_queue->front = (task_queue->front + 1) % (MAX_THREADS * 2);
    task_queue->count--;
    pthread_mutex_unlock(&task_queue->mutex);
    return result;
}
void handle_client(int sockfd, struct sockaddr_in addr) {
    config_t config;
    load_config(&config);
    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, addr_str, sizeof(addr_str));
    char *buffer = malloc(MAX_REQUEST_SIZE);
    if (!buffer) {
        send_response(sockfd, 500, "text/plain", "Internal Server Error", 21, 0, NULL, 0, NULL, 0, NULL, 0, -1);
        log_message(500, 21, "[%s] Memory allocation failed", addr_str);
        close(sockfd);
        return;
    }
    memset(buffer, 0, MAX_REQUEST_SIZE);
    int keep_alive = 1;
    size_t total_bytes_read = 0;
    time_t start_time = time(NULL);
    if (!check_rate_limit(addr_str)) {
        send_response(sockfd, 429, "text/plain", "Too Many Requests", 16, 0, NULL, 0, NULL, 0, NULL, 0, -1);
        log_message(429, 16, "[%s] Too Many Requests from IP", addr_str);
        free(buffer);
        close(sockfd);
        return;
    }
    while (keep_alive && !shutdown_flag) {
        if (time(NULL) - start_time > REQUEST_TIMEOUT) {
            send_response(sockfd, 408, "text/plain", "Request Timeout", 15, 0, NULL, 0, NULL, 0, NULL, 0, -1);
            log_message(408, 15, "[%s] Request Timeout", addr_str);
            keep_alive = 0;
            break;
        }
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        struct timeval tv = {KEEP_ALIVE_TIMEOUT, 0};
        int ready = select(sockfd + 1, &read_fds, NULL, NULL, &tv);
        if (ready <= 0) {
            keep_alive = 0;
            break;
        }
        ssize_t bytes_read = recv(sockfd, buffer + total_bytes_read, MAX_REQUEST_SIZE - total_bytes_read - 1, 0);
        if (bytes_read <= 0) {
            keep_alive = 0;
            break;
        }
        total_bytes_read += bytes_read;
        buffer[total_bytes_read] = '\0';
        if (strstr(buffer, "\r\n\r\n") == NULL && total_bytes_read < MAX_REQUEST_SIZE) {
            continue;
        }
        char *method = NULL, *path = NULL, *query = NULL, *headers = NULL, *body = NULL;
        size_t body_len = 0;
        time_t if_modified_since = -1;
        char etag[64] = {0};
        char user_agent[256] = {0};
        int keep_alive_timeout = KEEP_ALIVE_TIMEOUT;
        parse_request(buffer, total_bytes_read, &method, &path, &query, &headers, &body, &body_len, &if_modified_since, etag, sizeof(etag), user_agent, sizeof(user_agent), &keep_alive_timeout);
        if (!method || !path || strlen(path) > MAX_PATH_LEN || strlen(method) > 16) {
            send_response(sockfd, 400, "text/plain", "Bad Request", 11, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
            log_message(400, 11, "[%s] %s %s Bad Request (UA: %s)", addr_str, method ? method : "INVALID", path ? path : "INVALID", user_agent);
            keep_alive = 0;
            goto cleanup;
        }
        if (query && !sanitize_query(query)) {
            send_response(sockfd, 400, "text/plain", "Invalid Query String", 19, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
            log_message(400, 19, "[%s] %s %s Invalid Query String (UA: %s)", addr_str, method, path, user_agent);
            keep_alive = 0;
            goto cleanup;
        }
        log_message(0, 0, "[%s] %s %s (UA: %s)", addr_str, method, path, user_agent);
        char full_path[BUFFER_SIZE];
        if (secure_path(config.root_dir, path, full_path, sizeof(full_path)) != 0) {
            send_response(sockfd, 403, "text/plain", "Forbidden", 9, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
            log_message(403, 9, "[%s] %s %s Forbidden (UA: %s)", addr_str, method, path, user_agent);
            keep_alive = 0;
            goto cleanup;
        }
        struct stat st;
        int stat_res = stat(full_path, &st);
        if (body_len > config.max_body_size) {
            send_response(sockfd, 413, "text/plain", "Payload Too Large", 17, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
            log_message(413, 17, "[%s] %s %s Payload Too Large (UA: %s)", addr_str, method, path, user_agent);
            keep_alive = 0;
            goto cleanup;
        }
        int requires_auth = (strcmp(method, "PUT") == 0 || strcmp(method, "DELETE") == 0);
        if (requires_auth && !authenticate(headers)) {
            char header[BUFFER_SIZE];
            snprintf(header, sizeof(header), "WWW-Authenticate: Basic realm=\"Protected Area\"\r\n");
            send_response(sockfd, 401, "text/plain", "Unauthorized", 13, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
            send(sockfd, header, strlen(header), 0);
            log_message(401, 13, "[%s] %s %s Unauthorized (UA: %s)", addr_str, method, path, user_agent);
            keep_alive = 0;
            goto cleanup;
        }
        char file_etag[64] = {0};
        int is_head = strcmp(method, "HEAD") == 0;
        int is_get_or_head = (strcmp(method, "GET") == 0 || is_head);
        int use_gzip = (headers && strstr(headers, "Accept-Encoding: gzip") && is_get_or_head && stat_res == 0 && S_ISREG(st.st_mode));
        off_t range_start = 0, range_end = -1;
        int is_range = is_get_or_head && stat_res == 0 && S_ISREG(st.st_mode) && parse_range_header(headers, st.st_size, &range_start, &range_end);
        if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
            const char *health_response = "{\"status\":\"ok\",\"server\":\"GrokHTTPServer/1.1\"}";
            send_response(sockfd, 200, "application/json", health_response, strlen(health_response), 0, NULL, keep_alive, NULL, use_gzip, user_agent, 0, -1);
            log_message(200, strlen(health_response), "[%s] %s %s Health check (UA: %s)", addr_str, method, path, user_agent);
            continue;
        }
        if (stat_res == 0 && is_get_or_head) {
            const char *ext = strrchr(full_path, '.');
            if (ext && (strcasecmp(ext, ".exe") == 0 || strcasecmp(ext, ".sh") == 0 || strcasecmp(ext, ".php") == 0 || strcasecmp(ext, ".cgi") == 0)) {
                send_response(sockfd, 403, "text/plain", "Forbidden", 9, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                log_message(403, 9, "[%s] %s %s Forbidden executable (UA: %s)", addr_str, method, path, user_agent);
                keep_alive = 0;
                goto cleanup;
            }
            generate_etag(full_path, &st, file_etag, sizeof(file_etag));
            if (etag[0] && strcmp(etag, file_etag) == 0) {
                send_response(sockfd, 304, "text/plain", "", 0, is_head, NULL, keep_alive, file_etag, 0, user_agent, 0, -1);
                log_message(304, 0, "[%s] %s %s Not Modified (ETag) (UA: %s)", addr_str, method, path, user_agent);
                continue;
            }
        }
        if (strcmp(method, "PUT") == 0) {
            if (path[strlen(path) - 1] == '/') {
                if (mkdir(full_path, 0755) != 0 && errno != EEXIST) {
                    send_response(sockfd, 500, "text/plain", "Internal Server Error", 21, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                    log_message(500, 21, "[%s] %s %s Failed to create directory (UA: %s)", addr_str, method, path, user_agent);
                } else {
                    send_response(sockfd, stat_res == 0 ? 200 : 201, "text/plain", "OK", 2, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                    log_message(stat_res == 0 ? 200 : 201, 2, "[%s] %s %s Directory created (UA: %s)", addr_str, method, path, user_agent);
                }
            } else {
                if (stat_res == 0 && !S_ISREG(st.st_mode)) {
                    send_response(sockfd, 403, "text/plain", "Forbidden", 9, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                    log_message(403, 9, "[%s] %s %s Not a regular file (UA: %s)", addr_str, method, path, user_agent);
                } else {
                    int fd = open(full_path, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, 0644);
                    if (fd < 0 && errno == EEXIST) {
                        fd = open(full_path, O_WRONLY | O_TRUNC, 0644);
                    }
                    if (fd < 0 || write(fd, body, body_len) != (ssize_t)body_len) {
                        send_response(sockfd, 500, "text/plain", "Internal Server Error", 21, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                        log_message(500, 21, "[%s] %s %s Failed to write file (UA: %s)", addr_str, method, path, user_agent);
                    } else {
                        send_response(sockfd, stat_res == 0 ? 200 : 201, "text/plain", "OK", 2, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                        log_message(stat_res == 0 ? 200 : 201, 2, "[%s] %s %s File updated (UA: %s)", addr_str, method, path, user_agent);
                    }
                    close(fd);
                }
            }
        } else if (strcmp(method, "DELETE") == 0) {
            if (stat_res != 0 || !S_ISREG(st.st_mode) || unlink(full_path) != 0) {
                send_response(sockfd, stat_res == 0 ? 403 : 404, "text/plain", stat_res == 0 ? "Forbidden" : "Not Found", stat_res == 0 ? 9 : 9, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                log_message(stat_res == 0 ? 403 : 404, stat_res == 0 ? 9 : 9, "[%s] %s %s Failed to delete (UA: %s)", addr_str, method, path, user_agent);
            } else {
                send_response(sockfd, 200, "text/plain", "OK", 2, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                log_message(200, 2, "[%s] %s %s File deleted (UA: %s)", addr_str, method, path, user_agent);
            }
        } else if (stat_res != 0) {
            char error_path[BUFFER_SIZE] = "./404.html";
            struct stat error_st;
            if (stat(error_path, &error_st) == 0 && S_ISREG(error_st.st_mode)) {
                generate_etag(error_path, &error_st, file_etag, sizeof(file_etag));
                send_file(sockfd, error_path, 404, is_head, &error_st, keep_alive, file_etag, user_agent, 0, -1);
                log_message(404, error_st.st_size, "[%s] %s %s Custom 404 (UA: %s)", addr_str, method, path, user_agent);
            } else {
                send_response(sockfd, 404, "text/plain", "Not Found", 9, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                log_message(404, 9, "[%s] %s %s Not Found (UA: %s)", addr_str, method, path, user_agent);
            }
            continue;
        } else if (S_ISDIR(st.st_mode)) {
            char index_path[BUFFER_SIZE];
            snprintf(index_path, sizeof(index_path), "%s/index.html", full_path);
            if (access(index_path, R_OK) == 0) {
                strcpy(full_path, index_path);
                stat(full_path, &st);
                if (is_get_or_head) {
                    if (if_modified_since != -1 && st.st_mtime <= if_modified_since) {
                        send_response(sockfd, 304, "text/plain", "", 0, is_head, NULL, keep_alive, file_etag, 0, user_agent, 0, -1);
                        log_message(304, 0, "[%s] %s %s Not Modified (UA: %s)", addr_str, method, path, user_agent);
                    } else {
                        generate_etag(full_path, &st, file_etag, sizeof(file_etag));
                        send_file(sockfd, full_path, 200, is_head, &st, keep_alive, file_etag, user_agent, range_start, range_end);
                        log_message(is_range ? 206 : 200, is_range ? (range_end - range_start + 1) : st.st_size, "[%s] %s %s Served file%s (UA: %s)", addr_str, method, path, is_range ? " (Range)" : "", user_agent);
                    }
                } else {
                    send_response(sockfd, 405, "text/plain", "Method Not Allowed", 18, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                    log_message(405, 18, "[%s] %s %s Method Not Allowed (UA: %s)", addr_str, method, path, user_agent);
                }
            } else if (is_get_or_head) {
                send_dir_listing(sockfd, full_path, path, keep_alive, user_agent);
                log_message(200, 0, "[%s] %s %s Directory listing (UA: %s)", addr_str, method, path, user_agent);
            } else {
                send_response(sockfd, 405, "text/plain", "Method Not Allowed", 18, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
                log_message(405, 18, "[%s] %s %s Method Not Allowed (UA: %s)", addr_str, method, path, user_agent);
            }
        } else if (is_get_or_head) {
            if (if_modified_since != -1 && st.st_mtime <= if_modified_since) {
                send_response(sockfd, 304, "text/plain", "", 0, is_head, NULL, keep_alive, file_etag, 0, user_agent, 0, -1);
                log_message(304, 0, "[%s] %s %s Not Modified (UA: %s)", addr_str, method, path, user_agent);
            } else {
                generate_etag(full_path, &st, file_etag, sizeof(file_etag));
                send_file(sockfd, full_path, is_range ? 206 : 200, is_head, &st, keep_alive, file_etag, user_agent, range_start, range_end);
                log_message(is_range ? 206 : 200, is_range ? (range_end - range_start + 1) : st.st_size, "[%s] %s %s Served file%s (UA: %s)", addr_str, method, path, is_range ? " (Range)" : "", user_agent);
            }
        } else if (strcmp(method, "POST") == 0) {
            char *content_type = "text/plain";
            char *ct = strstr(headers, "Content-Type:");
            if (ct) {
                ct += 13;
                while (*ct == ' ') ct++;
                char *end = strchr(ct, '\r');
                if (end) *end = '\0';
                if (strncmp(ct, "application/json", 16) == 0) content_type = "application/json";
            }
            char *response_body = body ? body : "";
            size_t response_len = body_len;
            char *compressed = NULL;
            size_t compressed_len = 0;
            if (use_gzip && (strncmp(content_type, "text/", 5) == 0 || strcmp(content_type, "application/json") == 0)) {
                if (gzip_compress(response_body, response_len, &compressed, &compressed_len) == 0) {
                    response_body = compressed;
                    response_len = compressed_len;
                }
            }
            send_response(sockfd, 200, content_type, response_body, response_len, 0, NULL, keep_alive, NULL, compressed ? 1 : 0, user_agent, 0, -1);
            log_message(200, response_len, "[%s] %s %s Echoed POST data (UA: %s)", addr_str, method, path, user_agent);
            if (compressed) free(compressed);
        } else if (strcmp(method, "OPTIONS") == 0) {
            send_response(sockfd, 200, "text/plain", "", 0, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
            log_message(200, 0, "[%s] %s %s OPTIONS response (UA: %s)", addr_str, method, path, user_agent);
        } else {
            send_response(sockfd, 405, "text/plain", "Method Not Allowed", 18, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
            log_message(405, 18, "[%s] %s %s Method Not Allowed (UA: %s)", addr_str, method, path, user_agent);
        }
        if (headers && strstr(headers, "Connection: close")) {
            keep_alive = 0;
        }
cleanup:
        total_bytes_read = 0;
        memset(buffer, 0, MAX_REQUEST_SIZE);
    }
    free(buffer);
    close(sockfd);
}
void send_response(int sockfd, int status, const char *content_type, const char *body, size_t body_len, int is_head, struct stat *st, int keep_alive, const char *etag, int use_gzip, const char *user_agent, off_t range_start, off_t range_end) {
    char header[BUFFER_SIZE], date[64], last_mod[64], etag_header[128], range_header[128];
    get_http_date(date, sizeof(date));
    if (st) {
        struct tm *tm = gmtime(&st->st_mtime);
        strftime(last_mod, sizeof(last_mod), "%a, %d %b %Y %H:%M:%S GMT", tm);
    } else {
        strcpy(last_mod, "");
    }
    if (etag) {
        snprintf(etag_header, sizeof(etag_header), "ETag: \"%s\"", etag);
    } else {
        etag_header[0] = '\0';
    }
    if (range_start >= 0 && range_end >= range_start) {
        snprintf(range_header, sizeof(range_header), "Content-Range: bytes %ld-%ld/%ld\r\nAccept-Ranges: bytes", range_start, range_end, st ? st->st_size : 0);
    } else {
        range_header[0] = '\0';
    }
    const char *status_text =
        (status == 200) ? "OK" :
        (status == 201) ? "Created" :
        (status == 206) ? "Partial Content" :
        (status == 304) ? "Not Modified" :
        (status == 400) ? "Bad Request" :
        (status == 401) ? "Unauthorized" :
        (status == 403) ? "Forbidden" :
        (status == 404) ? "Not Found" :
        (status == 405) ? "Method Not Allowed" :
        (status == 408) ? "Request Timeout" :
        (status == 413) ? "Payload Too Large" :
        (status == 429) ? "Too Many Requests" :
        (status == 500) ? "Internal Server Error" : "Unknown";
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Date: %s\r\n"
             "Server: %s\r\n"
             "Last-Modified: %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Connection: %s\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Content-Security-Policy: default-src 'self'\r\n"
             "Strict-Transport-Security: max-age=31536000\r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: SAMEORIGIN\r\n"
             "X-XSS-Protection: 1; mode=block\r\n"
             "%s\r\n"
             "%s\r\n",
             status, status_text, date, SERVER_NAME,
             last_mod, content_type ? content_type : "text/plain", body_len,
             keep_alive ? "keep-alive" : "close", etag_header, range_header,
             use_gzip ? "Content-Encoding: gzip\r\n" : "");
    send(sockfd, header, strlen(header), 0);
    if (!is_head && body_len > 0) {
        send(sockfd, body, body_len, 0);
    }
}
void send_file(int sockfd, const char *full_path, int status, int is_head, struct stat *st, int keep_alive, const char *etag, const char *user_agent, off_t range_start, off_t range_end) {
    if (access(full_path, R_OK) != 0) {
        send_response(sockfd, 403, "text/plain", "Forbidden", 9, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
        return;
    }
    char *content_type = get_mime_type(full_path);
    char *body = NULL;
    size_t body_len = (range_start >= 0 && range_end >= range_start) ? (range_end - range_start + 1) : st->st_size;
    int use_gzip = (strncmp(content_type, "text/", 5) == 0 || strcmp(content_type, "application/json") == 0);
    if (use_gzip && !is_head && status != 304) {
        int fd = open(full_path, O_RDONLY);
        if (fd >= 0) {
            char *file_data = malloc(st->st_size);
            if (file_data && read(fd, file_data, st->st_size) == st->st_size) {
                char *compressed;
                size_t compressed_len;
                if (gzip_compress(file_data + range_start, body_len, &compressed, &compressed_len) == 0) {
                    body = compressed;
                    body_len = compressed_len;
                }
            }
            if (file_data) free(file_data);
            close(fd);
        }
    }
    send_response(sockfd, status, content_type, body, body_len, is_head, st, keep_alive, etag, body ? 1 : 0, user_agent, range_start, range_end);
    if (!is_head && status != 304 && !body) {
        int fd = open(full_path, O_RDONLY);
        if (fd >= 0) {
            if (range_start >= 0 && range_end >= range_start) {
                lseek(fd, range_start, SEEK_SET);
            }
            char buf[BUFFER_SIZE];
            size_t remaining = body_len;
            while (remaining > 0) {
                ssize_t bytes = read(fd, buf, remaining < sizeof(buf) ? remaining : sizeof(buf));
                if (bytes <= 0) break;
                send(sockfd, buf, bytes, 0);
                remaining -= bytes;
            }
            close(fd);
        }
    }
    if (body) free(body);
}
int compare_dirent(const void *a, const void *b) {
    const struct dirent *entry_a = *(const struct dirent **)a;
    const struct dirent *entry_b = *(const struct dirent **)b;
    return strcmp(entry_a->d_name, entry_b->d_name);
}
void send_dir_listing(int sockfd, const char *full_path, const char *req_path, int keep_alive, const char *user_agent) {
    DIR *dir = opendir(full_path);
    if (!dir) {
        send_response(sockfd, 403, "text/plain", "Forbidden", 9, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
        return;
    }
    struct dirent **entries;
    int n = scandir(full_path, &entries, NULL, compare_dirent);
    if (n < 0) {
        closedir(dir);
        send_response(sockfd, 500, "text/plain", "Internal Server Error", 21, 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
        return;
    }
    char body[BUFFER_SIZE * 4] = {0};
    strncat(body, "<html><head><title>Directory Listing</title></head><body><h1>Directory: ", sizeof(body) - strlen(body) - 1);
    char *escaped_path = malloc(strlen(req_path) * 3 + 1);
    char *p = escaped_path;
    for (const char *c = req_path; *c; c++) {
        if (*c == '<') { strcpy(p, "&lt;"); p += 4; }
        else if (*c == '>') { strcpy(p, "&gt;"); p += 4; }
        else if (*c == '&') { strcpy(p, "&amp;"); p += 5; }
        else *p++ = *c;
    }
    *p = '\0';
    strncat(body, escaped_path, sizeof(body) - strlen(body) - 1);
    free(escaped_path);
    strncat(body, "</h1><ul>", sizeof(body) - strlen(body) - 1);
    for (int i = 0; i < n; i++) {
        if (strcmp(entries[i]->d_name, ".") == 0 || strcmp(entries[i]->d_name, "..") == 0) continue;
        char link[BUFFER_SIZE];
        char *escaped_name = malloc(strlen(entries[i]->d_name) * 3 + 1);
        p = escaped_name;
        for (const char *c = entries[i]->d_name; *c; c++) {
            if (*c == '<') { strcpy(p, "&lt;"); p += 4; }
            else if (*c == '>') { strcpy(p, "&gt;"); p += 4; }
            else if (*c == '&') { strcpy(p, "&amp;"); p += 5; }
            else *p++ = *c;
        }
        *p = '\0';
        snprintf(link, sizeof(link), "<li><a href=\"%s/%s\">%s</a></li>", req_path, entries[i]->d_name, escaped_name);
        strncat(body, link, sizeof(body) - strlen(body) - 1);
        free(escaped_name);
        free(entries[i]);
    }
    free(entries);
    strncat(body, "</ul></body></html>", sizeof(body) - strlen(body) - 1);
    closedir(dir);
    char *compressed = NULL;
    size_t compressed_len = 0;
    if (gzip_compress(body, strlen(body), &compressed, &compressed_len) == 0) {
        send_response(sockfd, 200, "text/html", compressed, compressed_len, 0, NULL, keep_alive, NULL, 1, user_agent, 0, -1);
        free(compressed);
    } else {
        send_response(sockfd, 200, "text/html", body, strlen(body), 0, NULL, keep_alive, NULL, 0, user_agent, 0, -1);
    }
}
void parse_request(char *request, size_t bytes_read, char **method, char **path, char **query, char **headers, char **body, size_t *body_len, time_t *if_modified_since, char *etag, size_t etag_size, char *user_agent, size_t user_agent_size, int *keep_alive_timeout) {
    *method = strtok(request, " ");
    char *uri = strtok(NULL, " ");
    char *version = strtok(NULL, "\r\n");
    if (!version || (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0)) {
        return;
    }
    *path = uri;
    char *q = strchr(uri, '?');
    if (q) {
        *q = '\0';
        *query = q + 1;
    } else {
        *query = NULL;
    }
    *headers = strtok(NULL, "\r\n\r\n");
    if (*headers == NULL) return;
    *body = *headers + strlen(*headers) + 4;
    *body_len = bytes_read - (*body - request);
    char *cl = strstr(*headers, "Content-Length:");
    if (cl) {
        cl += 15;
        while (*cl == ' ') cl++;
        if (strlen(cl) > MAX_HEADER_FIELD) return;
        *body_len = atoi(cl);
    }
    char *ims = strstr(*headers, "If-Modified-Since:");
    if (ims) {
        ims += 18;
        while (*ims == ' ') ims++;
        if (strlen(ims) > MAX_HEADER_FIELD) return;
        struct tm tm = {0};
        if (strptime(ims, "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
            *if_modified_since = mktime(&tm);
        }
    }
    char *if_none_match = strstr(*headers, "If-None-Match:");
    if (if_none_match) {
        if_none_match += 14;
        while (*if_none_match == ' ') if_none_match++;
        if (strlen(if_none_match) > MAX_HEADER_FIELD) return;
        char *end = strchr(if_none_match, '\r');
        if (end) *end = '\0';
        strncpy(etag, if_none_match, etag_size - 1);
        etag[etag_size - 1] = '\0';
        if (etag[0] == '"') {
            memmove(etag, etag + 1, strlen(etag));
            char *quote = strchr(etag, '"');
            if (quote) *quote = '\0';
        }
    }
    char *ua = strstr(*headers, "User-Agent:");
    if (ua) {
        ua += 11;
        while (*ua == ' ') ua++;
        if (strlen(ua) > MAX_HEADER_FIELD) return;
        char *end = strchr(ua, '\r');
        if (end) *end = '\0';
        strncpy(user_agent, ua, user_agent_size - 1);
        user_agent[user_agent_size - 1] = '\0';
    }
    char *ka = strstr(*headers, "Keep-Alive:");
    if (ka) {
        ka += 11;
        while (*ka == ' ') ka++;
        if (strncmp(ka, "timeout=", 8) == 0) {
            ka += 8;
            *keep_alive_timeout = atoi(ka);
            if (*keep_alive_timeout < 1 || *keep_alive_timeout > KEEP_ALIVE_TIMEOUT) {
                *keep_alive_timeout = KEEP_ALIVE_TIMEOUT;
            }
        }
    }
}
char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "text/plain";
    if (strcasecmp(ext, ".html") == 0 || strcasecmp(ext, ".htm") == 0) return "text/html";
    if (strcasecmp(ext, ".css") == 0) return "text/css";
    if (strcasecmp(ext, ".js") == 0) return "application/javascript";
    if (strcasecmp(ext, ".json") == 0) return "application/json";
    if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(ext, ".png") == 0) return "image/png";
    if (strcasecmp(ext, ".gif") == 0) return "image/gif";
    if (strcasecmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcasecmp(ext, ".pdf") == 0) return "application/pdf";
    if (strcasecmp(ext, ".txt") == 0) return "text/plain";
    if (strcasecmp(ext, ".mp3") == 0) return "audio/mpeg";
    if (strcasecmp(ext, ".mp4") == 0) return "video/mp4";
    if (strcasecmp(ext, ".xml") == 0) return "application/xml";
    if (strcasecmp(ext, ".zip") == 0) return "application/zip";
    if (strcasecmp(ext, ".doc") == 0 || strcasecmp(ext, ".docx") == 0) return "application/msword";
    if (strcasecmp(ext, ".xls") == 0 || strcasecmp(ext, ".xlsx") == 0) return "application/vnd.ms-excel";
    return "application/octet-stream";
}
void generate_etag(const char *path, struct stat *st, char *etag, size_t etag_size) {
    snprintf(etag, etag_size, "%lx-%lx", (unsigned long)st->st_mtime, (unsigned long)st->st_size);
}
void log_message(int status, size_t bytes_sent, const char *format, ...) {
    if (!log_file) return;
    char timestamp[64];
    get_http_date(timestamp, sizeof(timestamp));
    fprintf(log_file, "[%s] ", timestamp);
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    if (status > 0) {
        fprintf(log_file, " [Status: %d, Bytes: %zu]", status, bytes_sent);
    }
    fprintf(log_file, "\n");
    fflush(log_file);
}
int secure_path(const char *root_dir, const char *path, char *full_path, size_t full_path_size) {
    char resolved_path[MAX_PATH_LEN];
    snprintf(full_path, full_path_size, ".%s", path);
    long path_max = pathconf(".", _PC_PATH_MAX);
    if (path_max == -1) path_max = MAX_PATH_LEN;
    char *resolved = realpath(full_path, resolved_path);
    if (!resolved) {
        return -1;
    }
    if (strncmp(resolved_path, root_dir, strlen(root_dir)) != 0) {
        return -1;
    }
    if (strlen(resolved_path) >= full_path_size) {
        return -1;
    }
    strncpy(full_path, resolved_path, full_path_size);
    return 0;
}
int sanitize_query(char *query) {
    if (!query) return 1;
    for (char *p = query; *p; p++) {
        if (*p == '<' || *p == '>' || *p == '&' || *p == '"' || *p == '\'') {
            return 0;
        }
    }
    return 1;
}
void signal_handler(int sig) {
    (void)sig;
    shutdown_flag = 1;
}
