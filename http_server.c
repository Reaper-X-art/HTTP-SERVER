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
#include <ctype.h>
#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_THREADS 100
#define ROOT_DIR "."
typedef struct {
int sockfd;
struct sockaddr_in addr;
} client_t;
void *handle_client(void *arg);
void send_response(int sockfd, int status, const char *content_type, const char *body, size_t body_len);
void parse_request(char *request, char **method, char **path, char **headers);
char *get_mime_type(const char *path);
void trim(char *str);
int main() {
int server_sock, client_sock;
struct sockaddr_in server_addr, client_addr;
socklen_t addr_len = sizeof(client_addr);
pthread_t threads[MAX_THREADS];
int thread_count = 0;
server_sock = socket(AF_INET, SOCK_STREAM, 0);
if (server_sock < 0) {
perror("Socket creation failed");
exit(EXIT_FAILURE);
}
memset(&server_addr, 0, sizeof(server_addr));
server_addr.sin_family = AF_INET;
server_addr.sin_addr.s_addr = INADDR_ANY;
server_addr.sin_port = htons(PORT);
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
printf("Server listening on port %d\n", PORT);
while (1) {
client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
if (client_sock < 0) {
perror("Accept failed");
continue;
}
client_t *client = malloc(sizeof(client_t));
client->sockfd = client_sock;
client->addr = client_addr;
if (pthread_create(&threads[thread_count++], NULL, handle_client, client) != 0) {
perror("Thread creation failed");
free(client);
close(client_sock);
}
if (thread_count >= MAX_THREADS) {
for (int i = 0; i < MAX_THREADS; i++) {
pthread_join(threads[i], NULL);
}
thread_count = 0;
}
}
close(server_sock);
return 0;
}
void *handle_client(void *arg) {
client_t *client = (client_t *)arg;
char buffer[BUFFER_SIZE] = {0};
ssize_t bytes_read;
bytes_read = recv(client->sockfd, buffer, BUFFER_SIZE - 1, 0);
if (bytes_read <= 0) {
close(client->sockfd);
free(client);
return NULL;
}
char *method = NULL, *path = NULL, *headers = NULL;
parse_request(buffer, &method, &path, &headers);
if (!method || !path) {
send_response(client->sockfd, 400, "text/plain", "Bad Request", 11);
goto cleanup;
}
if (strcmp(method, "GET") == 0) {
if (strstr(path, "..")) {
send_response(client->sockfd, 403, "text/plain", "Forbidden", 9);
goto cleanup;
}
char full_path[BUFFER_SIZE];
snprintf(full_path, sizeof(full_path), "%s%s", ROOT_DIR, strcmp(path, "/") == 0 ? "/index.html" : path);
struct stat st;
if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) {
send_response(client->sockfd, 404, "text/plain", "Not Found", 9);
goto cleanup;
}
int fd = open(full_path, O_RDONLY);
if (fd < 0) {
send_response(client->sockfd, 500, "text/plain", "Internal Server Error", 21);
goto cleanup;
}
char *body = malloc(st.st_size);
if (read(fd, body, st.st_size) != st.st_size) {
free(body);
close(fd);
send_response(client->sockfd, 500, "text/plain", "Internal Server Error", 21);
goto cleanup;
}
close(fd);
char *mime = get_mime_type(full_path);
send_response(client->sockfd, 200, mime, body, st.st_size);
free(body);
} else if (strcmp(method, "POST") == 0) {
char *body_start = strstr(buffer, "\r\n\r\n");
if (body_start) {
body_start += 4;
size_t body_len = bytes_read - (body_start - buffer);
send_response(client->sockfd, 200, "text/plain", body_start, body_len);
} else {
send_response(client->sockfd, 400, "text/plain", "Bad Request", 11);
}
} else {
send_response(client->sockfd, 405, "text/plain", "Method Not Allowed", 18);
}
cleanup:
close(client->sockfd);
free(client);
return NULL;
}
void send_response(int sockfd, int status, const char *content_type, const char *body, size_t body_len) {
char header[BUFFER_SIZE];
const char *status_text =
(status == 200) ? "OK" :
(status == 400) ? "Bad Request" :
(status == 403) ? "Forbidden" :
(status == 404) ? "Not Found" :
(status == 405) ? "Method Not Allowed" :
(status == 500) ? "Internal Server Error" : "Unknown";
snprintf(header, sizeof(header),
"HTTP/1.1 %d %s\r\n"
"Content-Type: %s\r\n"
"Content-Length: %zu\r\n"
"Connection: close\r\n\r\n",
status, status_text, content_type, body_len);
send(sockfd, header, strlen(header), 0);
if (body_len > 0) {
send(sockfd, body, body_len, 0);
}
}
void parse_request(char *request, char **method, char **path, char **headers) {
*method = strtok(request, " ");
*path = strtok(NULL, " ");
char *version = strtok(NULL, "\r\n");
*headers = strtok(NULL, "");
(void)version;
}
char *get_mime_type(const char *path) {
const char *ext = strrchr(path, '.');
if (!ext) return "text/plain";
if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
if (strcmp(ext, ".css") == 0) return "text/css";
if (strcmp(ext, ".js") == 0) return "application/javascript";
if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
if (strcmp(ext, ".png") == 0) return "image/png";
if (strcmp(ext, ".gif") == 0) return "image/gif";
if (strcmp(ext, ".txt") == 0) return "text/plain";
return "application/octet-stream";
}
void trim(char *str) {
char *end = str + strlen(str) - 1;
while (end > str && isspace(*end)) *end-- = '\0';
while (*str && isspace(*str)) str++;
}
