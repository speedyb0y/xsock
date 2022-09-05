/*

    TODO: TCP NO DELAY ?
*/

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>

#define foreach(_i, _n) for (uint _i = 0; _i != (_n); _i++)

#define __unused __attribute__((unused))

#define loop while(1)

#define elif(c) else if (c)

#define ASSERT(c) ({ if (!(c)) { write(STDOUT_FILENO, #c "\n", sizeof(#c)); abort(); } })

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define dbg(msg, ...) ({ printf("DEBUG: " msg "\n", ##__VA_ARGS__); })
#else
#define dbg(msg, ...) ({ })
#endif

#define dbg_conn(msg, ...) dbg("CONN[%p] " msg, conn, ##__VA_ARGS__)

#define fatal(msg, ...) ({ printf("FATAL: " msg "\n", ##__VA_ARGS__); exit(1); })

typedef unsigned int uint;
typedef long long int intll;
typedef unsigned long long int uintll;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct sockaddr sockaddr_s;
typedef struct sockaddr_in sockaddr_in_s;
typedef struct sockaddr_in6 sockaddr_in6_s;
typedef struct signalfd_siginfo signalfd_siginfo_s;
typedef struct epoll_event epoll_event_s;

#define IP4(a, b, c, d) ( \
    ((uint)(a) << 24) | \
    ((uint)(b) << 16) | \
    ((uint)(c) << 8) | \
    ((uint)(d)))

#define IP4_FMT(x) \
    (((x) >> 24) & 0xFF), \
    (((x) >> 16) & 0xFF), \
    (((x) >>  8) & 0xFF), \
    ( (x)        & 0xFF)

#define CONN_DO_ESTABLISHED 0
#define CONN_DO_REQUEST     1
#define CONN_DO_CONNECT     2 // WAITING FOR CONNECTION TO SERVER/PROXY
#define CONN_DO_REQUEST2    3

#define CONNS_N 32000

#define CONN_FD_MAX 0xFFFF

#define ESTABLISHED_BUFF_SIZE (2*1024*1024)

typedef struct conn_s {
    u8  status;
    u8  dst6; // IS THE THE DEST IPV6?
    u16 srv; // SOCKET FD
    u16 clt; // SOCKET FD
    u16 dstPort;
    u64 timeout;
    union {
        u8  dstIP[16];
        u32 dstIP4;
        u64 dstIP6[2];
    };
} conn_s;


typedef int (*xsock_conn_f) (conn_s*);

#define FAILED 0
#define WAIT 1

static int efd;
static u64 wakeAt;
static u64 now;

static uint fdsReady;
static u64 fds[(CONN_FD_MAX + 64 - 1)/(8 * sizeof(u64))];

static inline int xsock_epoll_ready (const int fd) {

    ASSERT(fd >= 3);
    ASSERT(fd < CONN_FD_MAX);
    ASSERT(fdsReady < CONN_FD_MAX);

    return !!(fds[fd/64] & (1ULL << (fd % 64)));
}

// TODO: REVISAR SE ESTÁ REALMENTE CONSUMINDO TUDO SENão vai ficar em um loop infinito executando o epoll() por 0ms
static inline void xsock_epoll_del (const int fd) {

    ASSERT(fd >= 3);
    ASSERT(fd < CONN_FD_MAX);

    if (fds[fd/64] & (1ULL << (fd % 64))) {
        fds[fd/64] ^= 1ULL << (fd % 64);
        fdsReady--;
    }

    ASSERT(fdsReady < CONN_FD_MAX);
}

static inline void xsock_epoll_add (const int fd) {

    ASSERT(fd >= 3);
    ASSERT(fd < CONN_FD_MAX);

    if (!(fds[fd/64] & (1ULL << (fd % 64)))) {
        fds[fd/64] ^= 1ULL << (fd % 64);
        fdsReady++;
    }

    ASSERT(fdsReady < CONN_FD_MAX);
}

static inline u64 rdtsc (void) {
    uint lo;
    uint hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((u64)hi << 32) | lo;
}

// LE TUDO O QUE TIVER PARA LER - TEM QUE DEIXAR O SOCKET COMO EAGAIN
// FALHA E ESQUECE O QUE LEU SE A CONEXÃO TIVER SIDO FECHADA, OU SE DER ERRO, OU SE REALMENTE CHEGAR A LER TODO O TAMANHO
static uint read_all (const int fd, void* buff, const uint size) {

    if (!xsock_epoll_ready(fd))
        return 0;

    uint remaining = size;

    do {

        const int chunk = read(fd, buff, remaining);

        if (chunk == -1) {
            if (errno == EAGAIN) {
                xsock_epoll_del(fd);
                return size - remaining;
            }
            if (errno == ECONNRESET ||
                errno == EPIPE)
                return 0xFFFFFFU;
            fatal("READ ALL - READ - FAILED - %d - %s", errno, strerror(errno));
        }

        if (chunk == 0)
            return 0xFFFFFFU;

        buff += chunk;
        remaining -= chunk;

    } while (remaining);

    return 0xFFFFFFU;
}

static void xsock_epoll_register (const int fd) {

    xsock_epoll_del(fd);

    epoll_event_s event = { .data.fd = fd, .events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR };

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
        fatal("FAILED TO ADD FD %d TO EPOLL - %d - %s", fd, errno, strerror(errno));
}

static void xsock_epoll_register_connecting (const int fd) {

    xsock_epoll_del(fd);

    epoll_event_s event = { .data.fd = fd, .events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR | EPOLLOUT };

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
        fatal("FAILED TO ADD FD %d TO EPOLL - %d - %s", fd, errno, strerror(errno));
}

static void xsock_epoll_register_connected (const int fd) {

    epoll_event_s event = { .data.fd = fd, .events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR };

    if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event))
        fatal("FAILED TO ADD FD %d TO EPOLL - %d - %s", fd, errno, strerror(errno));
}

static int xsock_conn_established_ (const int in, const int out) {

    if (xsock_epoll_ready(in)) {
        xsock_epoll_del(in);

        static char buff[ESTABLISHED_BUFF_SIZE];

        int size = read(in, buff, ESTABLISHED_BUFF_SIZE);

        if (size == -1) {
            if (errno == EAGAIN)
                return WAIT;
            if (errno == ECONNRESET
             || errno == EPIPE
             || errno == ENETUNREACH
             || errno == EHOSTUNREACH
             || errno == ETIMEDOUT)
                return FAILED;
            fatal("ESTABLISHED - READ - FAILED - %d - %s", errno, strerror(errno));
        }

        if (size == 0)
            return FAILED;

        const void* pos = buff;

        do {
            const int chunk = write(out, pos, size);
            if (chunk == -1) { // TODO: sched_yield() E TENTAR SÓ MAIS UMA VEZ
                if (errno == EAGAIN
                 || errno == ECONNRESET
                 || errno == EPIPE
                 || errno == ENETUNREACH
                 || errno == EHOSTUNREACH
                 || errno == ETIMEDOUT)
                    return FAILED;
                fatal("ESTABLISHED - %d -> %d - WRITE - FAILED - %d - %s", in, out, errno, strerror(errno));
            }
            pos += chunk;
            size -= chunk;
        } while (size);
    }

    return WAIT;
}

static int xsock_conn_established (conn_s* const conn) {

    return // NOTE: USING & BECAUSE WE WANT TO FLUSH BOTH, AND ONLY THEN CONSIDER THE RESULTS
        xsock_conn_established_(conn->srv, conn->clt)
      & xsock_conn_established_(conn->clt, conn->srv)
      ;
}

static int xsock_conn_request (conn_s* const conn) {

    // USA UM BUFFER MAIOR PARA MANDAR LER A MAIS, E SE REALMENTE LER, SIGNIFICA QUE PODE NÃO TER CHEGADO AO EAGAIN
    u8 buff[256];

    const uint size = read_all(conn->clt, buff, sizeof(buff));

    if (size == 0)
        return WAIT;

    if (size < 2 ||
        size >= 8)
        return FAILED;

    // VERSION
    if (buff[0] != 5)
        return FAILED;

    // "\x05\x01\x00"
    // "\5\2\0\1" # O CURL MANDA ISSO

    if (write(conn->clt, "\x05\x00", 2) != 2)
        return FAILED;

    conn->timeout = now + 5*1000;
    conn->status = CONN_DO_REQUEST2;

    return WAIT;
}

static int xsock_conn_request2 (conn_s* const conn) {

    u8 buff[128];

    const int size = read_all(conn->clt, buff, sizeof(buff));

    if (size == 0)
        return WAIT;

    if (size >= 64)
        return FAILED;

    // TODO: QUE É O buff[2]? É RESERVED 0?

    // VERSION
    if (buff[0] != 0x05)
        return FAILED;

    // COMMAND
    if (buff[1] != 0x01)
        return FAILED;

    // ADDRESS
    union { sockaddr_in_s v4; sockaddr_in6_s v6; } srvAddr; int srvFamily;

    switch (buff[3]) {

        case 0x04:

            if (size != (4 + 16 + 2))
                return FAILED;

            srvFamily = AF_INET6;
            srvAddr.v6.sin6_family   = AF_INET6;
            srvAddr.v6.sin6_port     = *(u16*)(buff + 4 + 16);
            srvAddr.v6.sin6_flowinfo = 0;
            srvAddr.v6.sin6_scope_id = 0;
            memcpy(&srvAddr.v6.sin6_addr, buff + 4, 16);

            break;

        case 0x01:

            if (size != (4 + 4 + 2))
                return FAILED;

            srvFamily = AF_INET;
            srvAddr.v4.sin_family      = AF_INET;
            srvAddr.v4.sin_addr.s_addr = *(u32*)(buff + 4);
            srvAddr.v4.sin_port        = *(u16*)(buff + 4 + 4);

            break;

        default:
            return FAILED;
    }

    const int srv = socket(srvFamily, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);

    if (srv == -1)
        fatal("FAILED TO CREATE SOCKET - %d - %s", errno, strerror(errno));

    if (srv >= CONN_FD_MAX)
        fatal("SOCKET FD TOO HIGH - %d", srv);

    xsock_epoll_register_connecting(srv);

    conn->srv     = srv;
    conn->dst6    = srvFamily == AF_INET6; // PRECISA LEMBRAR PARA PODER MANDAR A RESPOSTA DEPOIS
    conn->timeout = now + 5*1000;
    conn->status  = CONN_DO_CONNECT;

    // TODO: SE CONECTAR AQUI, ENTÂO JÁ TEM QUE EXECUTR A PARADA
    if (!connect(conn->srv, (sockaddr_s*)&srvAddr,
        srvFamily == AF_INET ?
            sizeof(srvAddr.v4) :
            sizeof(srvAddr.v6)
        ))
        return FAILED;

    if (errno == EINPROGRESS)
        return WAIT;

    return FAILED;
}

static int xsock_conn_connect (conn_s* const conn) {

    if (!xsock_epoll_ready(conn->srv))
        return WAIT;

    int e; socklen_t optlen = sizeof(e);

    if (getsockopt(conn->srv, SOL_SOCKET, SO_ERROR, &e, &optlen))
        fatal("GETSOCKOPT() FAILED - %d - %s", errno, strerror(errno));

    if (e) {
        // TODO: SEND ERROR RESPONSE MESSAGE
        return FAILED;
    }

    xsock_epoll_register_connected(conn->srv);

    const uint size = conn->dst6 ? 22 : 10;

    const char* msg = conn->dst6 ?
        "\x05\x00\x00\x04" "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" "\x00\x00" :
        "\x05\x00\x00\x01" "\x00\x00\x00\x00" "\x00\x00"
        ;

    if (write(conn->clt, msg, size) != size)
        return FAILED;

    conn->timeout = 0;
    conn->status  = CONN_DO_ESTABLISHED;

    return xsock_conn_established(conn);
}

int main (void) {

    struct rlimit limit = {
        .rlim_cur = CONN_FD_MAX,
        .rlim_max = CONN_FD_MAX
    };

    if (setrlimit(RLIMIT_NOFILE, &limit))
        fatal("FAILED TO SET OPEN FILES LIMIT");

    int term = 0;

    fdsReady = 0;

    memset(fds, 0, sizeof(fds));

    // IGNORE SIGNALS
    struct sigaction action;

    memset(&action, 0, sizeof(action));

    action.sa_handler = SIG_IGN;

    for (int sig = 0; sig != NSIG; sig++)
        if (sig != SIGTERM
         && sig != SIGINT
         && sig != SIGQUIT)
        sigaction(sig, &action, NULL);

    sigset_t mask;

    // BLOCK SIGNALS
    sigfillset(&mask);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        fatal("");

    // RECEIVE SIGNALS VIA FD
    const int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

    if (sfd == -1)
        fatal("");

    if ((efd = epoll_create1(EPOLL_CLOEXEC)) == -1)
        fatal("FAILED TO CREATE EPOLL INSTANCE - %d - %s", errno, strerror(errno));

    xsock_epoll_register(sfd);

#if 0
    // IPV6_V6ONLY
    // /proc/sys/net/ipv6/bindv6only
    const int sock = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
#else
    const int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
#endif

    if (sock == -1)
        fatal("FAILED TO CREATE SOCKET - %d - %s", errno, strerror(errno));

    xsock_epoll_register(sock);

    { const int yes = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
            fatal("");
    }

#if 0
    const sockaddr_in6_s addr = {
       .sin6_family   = AF_INET6,
       .sin6_port     = htons(1080),
       .sin6_flowinfo = 0,
       .sin6_scope_id = 0,
       .sin6_addr     = { .s6_addr = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } },
    };
#else
    const sockaddr_in_s addr = {
        .sin_family = AF_INET,
        .sin_port = htons(1080),
        .sin_addr = { .s_addr = htonl(IP4(240,0,0,0)) }
    };
#endif
    if (bind(sock, (sockaddr_s*)&addr, sizeof(addr)))
        fatal("FALHOU: %s", strerror(errno));

    if (listen(sock, 256))
        fatal("FAILED TO LISTEN");

    conn_s conns[CONNS_N]; uint connsN = 0;

    do {

        struct timespec tp;

        if (clock_gettime(CLOCK_MONOTONIC, &tp))
            fatal("CLOCK_GETTIME() FAILED - %d - %s", errno, strerror(errno));

        now = 7ULL*24*60*60*1000 +
            (u64)tp.tv_sec*1000 +
            (u64)tp.tv_nsec/1000000
            ;

        wakeAt = now + 8*1000;

        // ACCEPT NEW CONNECTIONS
        if (xsock_epoll_ready(sock)) {
            xsock_epoll_del(sock);

            loop {

                union { sockaddr_in_s v4; sockaddr_in6_s v6; } addr; socklen_t addrlen = sizeof(addr);

                const int clt = accept4(sock, (sockaddr_s*)&addr, &addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);

                if (clt == -1) {
                    if (errno == EAGAIN)
                        break;
                    if (errno == ECONNABORTED
                     || errno == ETIMEDOUT)
                        continue;
                    fatal("ACCEPT - ACCEPT() FAILED - %d - %s", errno, strerror(errno));
                }

                if (clt >= CONN_FD_MAX)
                    fatal("ACCEPT - SOCKET FD TOO HIGH");

                // TODO: SE FOR O ENDEREÇO LOCAL, É PROXY, SENÃO, É TRANSPARENTE
                if (connsN != CONNS_N) {

                    xsock_epoll_register(clt);

                    conn_s* const conn = &conns[connsN++];

                    conn->clt     = clt;
                    conn->srv     = 0;
                    conn->dst6    = 0;
                    conn->dstPort = 0;
                    conn->timeout = now + 5*1000;
                    conn->status  = CONN_DO_REQUEST;
                } else
                    close(clt);
            }
        }

        // CONNECTIONS
        static const xsock_conn_f funcs [] = {
            /* CONN_DO_ESTABLISHED */ xsock_conn_established,
            /* CONN_DO_REQUEST     */ xsock_conn_request,
            /* CONN_DO_CONNECT     */ xsock_conn_connect,
            /* CONN_DO_REQUEST2    */ xsock_conn_request2,
        };

        uint i = 0;

        while (i != connsN) {

            conn_s* const conn = &conns[i];

            if (funcs[conn->status](conn)) {
                if (conn->timeout) {
                    if (conn->timeout <= now)
                        goto failed;
                    if (wakeAt > conn->timeout)
                        wakeAt = conn->timeout;
                }
                i++;
                continue;
            }

failed:
            xsock_epoll_del(conn->clt); if (conn->srv)
            xsock_epoll_del(conn->srv);

            close(conn->clt); if (conn->srv)
            close(conn->srv);

            if (i != --connsN)
                memcpy(conn, &conns[connsN], sizeof(conn_s));
        }

        // POLL FDS
        epoll_event_s events[1024];

        static int fastAgain = 1;

        fastAgain = fastAgain && fdsReady;

        int eventsN = epoll_wait(efd, events, 1024,
            fastAgain ? 100 : (
            (wakeAt >= now) ?
            (wakeAt -  now) : 0
            ));

        if (eventsN == -1) {
            if (errno != EINTR) // TODO: O STRACE ESTÁ CAUSANDO ISSO MESMO IGNORANDO OS SINAIS
                fatal("EPOLL WAIT FAILED: %d - %s", errno, strerror(errno));
        } elif (eventsN) {
            while (eventsN--)
                xsock_epoll_add(events[eventsN].data.fd);
            fastAgain = 1;
        } elif (fastAgain)
            fastAgain = 0;

        // SIGNALS
        if (xsock_epoll_ready(sfd)) {
            xsock_epoll_del(sfd);

            loop {

                signalfd_siginfo_s siginfo;

                const int size = read(sfd, &siginfo, sizeof(siginfo));

                if (size == -1) {
                    if (errno == EAGAIN)
                        break;
                    fatal("FAILED TO READ FROM SIGNAL FD - %d - %s", errno, strerror(errno));
                }

                if (size != sizeof(siginfo))
                    fatal("FAILED TO READ FROM SIGNAL FD");

                switch (siginfo.ssi_signo) {
                    case SIGTERM:
                    case SIGINT:
                    case SIGQUIT:
                        term = 1;
                }
            }
        }

    } while (!term);

    return 0;
}
