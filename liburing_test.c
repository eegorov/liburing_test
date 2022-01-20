#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <liburing.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#define SERVER_STRING           "Server: zerohttpd/0.1\r\n"
#define DEFAULT_SERVER_PORT     8000
#define QUEUE_DEPTH             256
#define READ_SZ                 8192


enum
{
    Event_Type_NewConnection  = 0,
    Event_Type_Timeout,
    Event_Type_ClientSocketReadyRead,
    Event_Type_ClientSockedWrited,
    Event_Type_ClientSockedClosed,
    Event_Type_FileWrited,
}
event_types;

#define EVENT_TYPE_ACCEPT       0
#define EVENT_TYPE_READ         1
#define EVENT_TYPE_WRITE        2

#define MIN_KERNEL_VERSION      5
#define MIN_MAJOR_VERSION       6

socklen_t client_addr_len = sizeof(struct sockaddr_in);

struct my_request {
    int event_type;
    int client_socket;
    int datalen;
    int file_descriptor;
    struct sockaddr_in client_addr;
    char filename[256];
    char data[READ_SZ];
};

struct io_uring ring;

/*
 One function that prints the system call and the error details
 and then exits with error code 1. Non-zero meaning things didn't go well.
 */
void fatal_error(const char *syscall) {
    perror(syscall);
    exit(1);
}

int check_kernel_version() {
    struct utsname buffer;
    char *p;
    long ver[16];
    int i=0;

    if (uname(&buffer) != 0) {
        perror("uname");
        exit(EXIT_FAILURE);
    }

    p = buffer.release;

    while (*p) {
        if (isdigit(*p)) {
            ver[i] = strtol(p, &p, 10);
            i++;
        } else {
            p++;
        }
    }
    printf("Minimum kernel version required is: %d.%d\n",
           MIN_KERNEL_VERSION, MIN_MAJOR_VERSION);
    if (ver[0] >= MIN_KERNEL_VERSION && ver[1] >= MIN_MAJOR_VERSION ) {
        printf("Your kernel version is: %ld.%ld\n", ver[0], ver[1]);
        return 0;
    }
    fprintf(stderr, "Error: your kernel version is: %ld.%ld\n",
            ver[0], ver[1]);
    return 1;
}

/*
 * This function is responsible for setting up the main listening socket used by the
 * web server.
 * */

int setup_listening_socket(int port) {
    int sock;
    struct sockaddr_in srv_addr;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        fatal_error("socket()");

    int enable = 1;
    if (setsockopt(sock,
                   SOL_SOCKET, SO_REUSEADDR,
                   &enable, sizeof(int)) < 0)
        fatal_error("setsockopt(SO_REUSEADDR)");


    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* We bind to a port and turn this socket into a listening
     * socket.
     * */
    if (bind(sock,
             (const struct sockaddr *)&srv_addr,
             sizeof(srv_addr)) < 0)
        fatal_error("bind()");

    if (listen(sock, 10) < 0)
        fatal_error("listen()");

    return (sock);
}

static void msec_to_ts(struct __kernel_timespec *ts, unsigned int msec)
{
    ts->tv_sec = msec / 1000;
    ts->tv_nsec = (msec % 1000) * 1000000;
}

struct __kernel_timespec ts;
int add_timeout_event(struct my_request *req)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);

    msec_to_ts(&ts, 5000);
    req->event_type = Event_Type_Timeout;

    io_uring_prep_timeout(sqe, &ts, 0, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int remove_timeout_event(struct my_request *req)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);

    io_uring_prep_timeout_remove(sqe, (__u64)&ts, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}


int add_accept_request(int server_socket, struct sockaddr_in *client_addr,
                       socklen_t *client_addr_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    // аналог accept
    io_uring_prep_accept(sqe, server_socket, (struct sockaddr *) client_addr,
                         client_addr_len, 0);
    struct my_request *req = malloc(sizeof(*req));
    req->event_type = Event_Type_NewConnection;
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);

    return 0;
}

int add_read_request(struct my_request *req, int client_socket)
{
    if(req == 0) // Новое подключение. Создадим новый запрос
    {
        struct sockaddr addr;
        socklen_t len = sizeof(addr);
        struct sockaddr_in * s_addr = (struct sockaddr_in *)&addr;
        int i = getpeername(client_socket, &addr, &len);
        if (i == 0)
        {
            char * ip = inet_ntoa(s_addr->sin_addr);
            uint16_t port = ntohs(s_addr->sin_port);
            req = malloc(sizeof(*req));
            fprintf(stderr, "req = %p\n", req);
            req->client_socket = client_socket;
            req->client_addr = *s_addr;
            sprintf(req->filename, "%s_%d.txt", ip, port);
            req->file_descriptor = open(req->filename, O_WRONLY|O_CREAT, S_IRUSR);
        }
    }
    req->datalen = READ_SZ;
    req->event_type = Event_Type_ClientSocketReadyRead;

    fprintf(stderr, "Waiting data from from client address: [%s:%u]\n", ip, port);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, client_socket, req->data, req->datalen, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

void server_loop(int server_socket)
{

    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    add_accept_request(server_socket, &client_addr, &client_addr_len); // Создание события на подключение нового клиента

    while (1)
    {
        int ret = io_uring_wait_cqe(&ring, &cqe);
        struct my_request *req = (struct my_request *) cqe->user_data;
        if (ret < 0)
            fatal_error("io_uring_wait_cqe");
//        if (cqe->res < 0) {
//            fprintf(stderr, "Async request failed: %s for event: %d\n",
//                    strerror(-cqe->res), req->event_type);
//            exit(1);
//        }


        printf("New event for req = %p\n", req);

        if(!req)
            continue;

        switch (req->event_type)
        {
        case Event_Type_NewConnection:
        {
            // В cqe->res лежит дискриптор подключения клиента
            add_accept_request(server_socket, &client_addr, &client_addr_len); // продолжим слушать
            add_read_request(0, cqe->res);
            free(req);
            break;
        }
        case Event_Type_ClientSocketReadyRead:
        {
            int readed = cqe->res;// В cqe->res лежит число считанных байт
            printf("Readed %d bytes for req = %p\n", readed, req);
            if (!readed)
            {
                // Сокет закрылся. Закроем файл.
                close(req->file_descriptor);
                free(req);
            }
            else
            {
                req->datalen = cqe->res;
                // Выставим таймаут в 5 сек для последующей записи данных в файл
                add_timeout_event(req);
            }
            break;
        }
        case Event_Type_Timeout:
        {
            int result = cqe->res; // Результат работы таймера
            printf("Timout expited for req = %p. result = %d, -ETIME = %d\n", req, result, -ETIME);
            if(result == -ETIME)
            {
                // Запишем в файл и продолжим слушать
                int count = write(req->file_descriptor, req->data, req->datalen);
                count = write(req->client_socket, req->data, req->datalen);
                remove_timeout_event(req);
            }
            else if(result == -2) // TODO: что такое -2  ?????
            {
                //
                add_read_request(req, req->client_socket);
            }
            break;
        }

        }
        /* Mark this request as processed */
        io_uring_cqe_seen(&ring, cqe);
    }
}

void sigint_handler(int signo) {
    printf("^C pressed. Shutting down.\n");
    io_uring_queue_exit(&ring);
    exit(0);
}

int main()
{
    if (check_kernel_version())
    {
        return EXIT_FAILURE;
    }

    int server_socket = setup_listening_socket(DEFAULT_SERVER_PORT);
    printf("Listening on port: %d\n", DEFAULT_SERVER_PORT);

    signal(SIGINT, sigint_handler);
    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    server_loop(server_socket);

    return 0;
}
