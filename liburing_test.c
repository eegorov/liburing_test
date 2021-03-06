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

#define MIN_KERNEL_VERSION      5
#define MIN_MAJOR_VERSION       6

#define DEFAULT_SERVER_PORT     8000
#define QUEUE_DEPTH             256
#define READ_SZ                 16*1024
#define TIMEOUT                 5000


enum
{
    EventType_NewConnection  = 0,
    EventType_Timeout,
    EventType_ClientSocketReaded,
    EventType_ClientSockedWrited,
    EventType_ClientSockedClosed,
    EventType_FileWrited,
} event_types;

socklen_t client_addr_len = sizeof(struct sockaddr_in);

struct my_request
{
    int event_type;
    int client_socket;
    int datalen;
    int file_descriptor;
    struct sockaddr_in client_addr;
    char filename[256];
    char data[READ_SZ];
};

struct io_uring ring;

void fatal_error(const char *syscall)
{
    perror(syscall);
    exit(1);
}

int check_kernel_version()
{
    struct utsname buffer;
    char *p;
    long ver[16];
    int i=0;

    if (uname(&buffer) != 0)
    {
        perror("uname");
        exit(EXIT_FAILURE);
    }

    p = buffer.release;

    while (*p)
    {
        if (isdigit(*p))
        {
            ver[i] = strtol(p, &p, 10);
            i++;
        }
        else
        {
            p++;
        }
    }
    printf("Minimum kernel version required is: %d.%d\n",
           MIN_KERNEL_VERSION, MIN_MAJOR_VERSION);
    if (ver[0] >= MIN_KERNEL_VERSION && ver[1] >= MIN_MAJOR_VERSION )
    {
        printf("Your kernel version is: %ld.%ld\n", ver[0], ver[1]);
        return 0;
    }
    fprintf(stderr, "Error: your kernel version is: %ld.%ld\n",
            ver[0], ver[1]);
    return 1;
}

int setup_listening_socket(int port)
{
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

    msec_to_ts(&ts, TIMEOUT);
    req->event_type = EventType_Timeout;

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

    io_uring_prep_accept(sqe, server_socket, (struct sockaddr *) client_addr,
                         client_addr_len, 0);
    struct my_request *req = malloc(sizeof(*req));
    req->event_type = EventType_NewConnection;
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);

    return 0;
}

struct my_request * create_req(int client_socket)
{
    struct my_request * req;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);
    struct sockaddr_in * s_addr = (struct sockaddr_in *)&addr;
    int i = getpeername(client_socket, &addr, &len);

    if(i != 0)
        return NULL;

    req = malloc(sizeof(*req));
    if(!req)
        return NULL;

    char * ip = inet_ntoa(s_addr->sin_addr);
    uint16_t port = ntohs(s_addr->sin_port);

    fprintf(stderr, "req = %p\n", req);
    req->client_socket = client_socket;
    req->client_addr = *s_addr;
    sprintf(req->filename, "%s_%d.txt", ip, port);
    req->file_descriptor = open(req->filename, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR);
    req->datalen = READ_SZ;

    return req;
}

int destroy_req(struct my_request * req)
{
    if(req->client_socket)
        close(req->client_socket);
    if(req->file_descriptor)
        close(req->file_descriptor);
    if(req)
        free(req);
}

int add_read_request(struct my_request *req)
{
    req->datalen = READ_SZ;
    req->event_type = EventType_ClientSocketReaded;

    fprintf(stderr, "Waiting data from from client address: %s\n", req->filename);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, req->client_socket, req->data, req->datalen, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_echo_request(struct my_request *req)
{
    req->event_type = EventType_ClientSockedWrited;

    fprintf(stderr, "Write data to client: %s\n", req->filename);
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_write(sqe, req->client_socket, req->data, req->datalen, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_log_request(struct my_request *req)
{
    req->event_type = EventType_FileWrited;

    fprintf(stderr, "Write data to log: %s\n", req->filename);
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_write(sqe, req->file_descriptor, req->data, req->datalen, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}


void server_loop(int server_socket)
{

    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    add_accept_request(server_socket, &client_addr, &client_addr_len); // ???????????????? ?????????????? ???? ?????????????????????? ???????????? ??????????????

    while (1)
    {
        int ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0)
        {
            fatal_error("io_uring_wait_cqe");
            exit(1);
        }

        struct my_request *req = (struct my_request *) cqe->user_data;

        printf("\n-----------------------------------------------------\n", req);
        printf("New event for req = %p\n", req);
        printf("--\n", req);

        if(!req)
        {
            io_uring_cqe_seen(&ring, cqe);
            continue;
        }

        switch (req->event_type)
        {
        case EventType_NewConnection:
        {
            // ?? cqe->res ?????????? ???????????????????? ?????????????????????? ??????????????
            add_accept_request(server_socket, &client_addr, &client_addr_len); // ?????????????????? ??????????????
            free(req);
            struct my_request * socket_req = create_req(cqe->res);
            if(socket_req)
            {
                add_read_request(req);
            }
            else
            {
                fatal_error("Can not allocate memory for request");
            }
            break;
        }
        case EventType_ClientSocketReaded:
        {
            int readed = cqe->res;// ?? cqe->res ?????????? ?????????? ?????????????????? ????????
            printf("Readed %d bytes for req = %p\n", readed, req);
            if (!readed)
            {
                // ?????????? ????????????????. ?????????????? ????????.
                destroy_req(req);
            }
            else
            {
                req->datalen = cqe->res;
                // ???????????????? ?????????????? ?? 5 ?????? ?????? ?????????????????????? ???????????? ???????????? ?? ????????
                add_timeout_event(req);
            }
            break;
        }
        case EventType_Timeout:
        {
            int result = cqe->res; // ?????????????????? ???????????? ??????????????
            printf("Timeout event for req = %p. result = %d, -ETIME = %d\n", req, result, -ETIME);
            if(result == -ETIME)
            {
                // ?????????????? ?? ???????? ?? ?????????????????? ??????????????
                add_echo_request(req);
            }
            break;
        }
        case EventType_ClientSockedWrited:
        {
            int result = cqe->res; // ???????????????????? ???????????????????? ?? ?????????? ????????
            printf("For req = %p writed %d bytes from %d\n", req, result, req->datalen);
            if(result < 0)
            {
                // ???????????? ???????????? ?? ??????????. ?????????????????? ??????????.
                destroy_req(req);
            }
            else
            {
                if(result != req->datalen)
                {
                    // ??????-???? ?????????? ???? ??????
                    // ???????? ???? ???????? ???? ???????? ???? ????????????????.
                    // ???? ?? ???????????????????? ?????????? ?????????????????????? ???????????????????? ???????????? "???? ??????????????????"
                    // ???????? ???????????? ??????????????????????????, ?????????????? ?? ?????? ???????????? ????, ?????? ?????????????? ??????????????????
                    req->datalen = result;
                }
                add_log_request(req);
            }
            break;
        }
        case EventType_FileWrited:
        {
            // ?????????????????? ???????????? ????????????
            add_read_request(req);
        }
        default: break;
        }

        io_uring_cqe_seen(&ring, cqe);
    }
}

void sigint_handler(int signo)
{
    if( signo == SIGHUP || signo == SIGPIPE)
    {
        printf("SIGNAL %d received. Ignoring...\n", signo);
        return;
    }
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
    signal(SIGHUP, sigint_handler);
    signal(SIGPIPE, sigint_handler);
    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    server_loop(server_socket);

    return 0;
}
