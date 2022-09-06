/*

    TODO: NO CLIENTE, VAI TER QUE ALTERAR A PORTA DE TEMPOS EM TEMPOS SE NAO ESTIVER FUNCIONANDO
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <net/addrconf.h>
#include <linux/module.h>

#if XCONF_XSOCK_ASSERT
#define XSOCK_ASSERT(c) ({ if (!(c)) printk("ASSERT FAILED: " #c "\n"); })
#else
#define XSOCK_ASSERT(c) ({})
#endif

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef unsigned long long int uintll;

typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct header_ops header_ops_s;
typedef struct net_device_ops net_device_ops_s;

#define SKB_TAIL(skb) PTR(skb_tail_pointer(skb))

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif(c) else if(c)

#define foreach(i, t) for (uint i = 0; i != (t); i++)

static inline u16 BE16(u16 x) { return __builtin_bswap16(x); }
static inline u32 BE32(u32 x) { return __builtin_bswap32(x); }
static inline u64 BE64(u64 x) { return __builtin_bswap64(x); }

#define CACHE_LINE_SIZE 64

#define __A6(x) (x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5]
#define __A4(x) (x)[0], (x)[1], (x)[2], (x)[3]

#define _MAC(x) __A6(x)
#define _IP4(x) __A4(x)

#define ARRAY_COUNT(a) (sizeof(a)/sizeof((a)[0]))

#define XSOCK_SERVER      XCONF_XSOCK_SERVER_IS
#define XSOCK_SERVER_PORT XCONF_XSOCK_SERVER_PORT
#define XSOCK_CONNS_N     XCONF_XSOCK_CONNS_N
#define XSOCK_PATHS_N     XCONF_XSOCK_PATHS_N

#if ! (1 <= XSOCK_SERVER_PORT && XSOCK_SERVER_PORT <= 0xFFFF)
#error "BAD XSOCK_SERVER_PORT"
#endif

#if ! (1 <= XSOCK_CONNS_N && XSOCK_CONNS_N <= 0xFFFF)
#error "BAD XSOCK_CONNS_N"
#endif

#if ! (1 <= XSOCK_PATHS_N && XSOCK_PATHS_N <= 4)
#error "BAD XSOCK_PATHS_N"
#endif

//
#define PORT(cid, pid) (XSOCK_SERVER_PORT + (cid)*10 + (pid))
#define PORT_CID(port) (((port) - XSOCK_SERVER_PORT) / 10)
#define PORT_PID(port) (((port) - XSOCK_SERVER_PORT) % 10)

//
#if PORT(XSOCK_CONNS_N - 1, XSOCK_PATHS_N - 1) > 0xFFFF
#error "BAD XSOCK_SERVER_PORT / XSOCK_CONNS_N / XSOCK_PATHS_N"
#endif

#define XSOCK_PATH_F_UP              0b0000000000000001U // ADMINISTRATIVELY
#define XSOCK_PATH_F_UP_AUTO         0b0000000000000010U // SE DER TIMEOUT VAI DESATIVAR ISSO
#define XSOCK_PATH_F_UP_ITFC         0b0000000000000100U // WATCH INTERFACE EVENTS AND SET THIS TODO: INICIALIZAR COMO 0 E CARREGAR ISSO NO DEVICE NOTIFIER
#if XSOCK_SERVER
#define XSOCK_PATH_F_ITFC_LEARN      0b0000000000001000U
#define XSOCK_PATH_F_MAC_LEARN       0b0000000000010000U
#define XSOCK_PATH_F_GW_LEARN        0b0000000000100000U
#define XSOCK_PATH_F_SADDR_LEARN     0b0000000001000000U
#define XSOCK_PATH_F_DADDR_LEARN     0b0000000010000000U    // TODO: TIME DO ULTIMO RECEBIDO; DESATIVAR O PATH NO SERVIDOR SE NAO RECEBER NADA EM TANTO TEMPO
#define XSOCK_PATH_F_DPORT_LEARN     0b0000000100000000U
#endif

#define FLAGS_IS_UP(f) (((f) & (XSOCK_PATH_F_UP | XSOCK_PATH_F_UP_AUTO | XSOCK_PATH_F_UP_ITFC)) \
                            == (XSOCK_PATH_F_UP | XSOCK_PATH_F_UP_AUTO | XSOCK_PATH_F_UP_ITFC))

// EXPECTED SIZE
#define XSOCK_WIRE_SIZE CACHE_LINE_SIZE

typedef struct xsock_wire_s {
    u8 _align[10];
    struct xsock_wire_eth_s {
        u8  dst[ETH_ALEN];
        u8  src[ETH_ALEN];
        u16 type;
    } eth;
    struct xsock_wire_ip_s {
        u8  version;
        u8  tos;
        u16 size;
        u16 hash; // A CHECKSUM TO CONFIRM THE INTEGRITY AND AUTHENTICITY OF THE PAYLOAD
        u16 frag;
        u8  ttl;
        u8  protocol;
        u16 cksum;
        u8  src[4];
        u8  dst[4];
    } ip;
    union {
        struct xsock_wire_tcp_s { // AS ORIGINAL TCP
            u16 src;
            u16 dst;
            u32 seq;
            u32 ack;
            u16 flags;
            u16 window;
            u16 checksum;
            u16 urgent;
        } tcp;
        struct xsock_wire_udp_s { // AS FAKE UDP
            u16 src;
            u16 dst; // THE XSOCK_SERVER PORT WILL DETERMINE THE CONN AND PATH
            u16 size;
            u16 cksum;
            u32 ack;
            u16 flags;
            u16 window;
            u32 seq;
        } udp;
    };
} xsock_wire_s;

// EXPECTED SIZE
#define XSOCK_PATH_SIZE CACHE_LINE_SIZE

typedef struct xsock_path_s {
    net_device_s* itfc;
#if XSOCK_SERVER
    u64 hash; // THE PATH HASH
#else
    u64 reserved;
#endif
    u16 flags;
    u16 pkts;
    u16 sport;
    u16 dport; // THE XSOCK_SERVER PORT WILL DETERMINE THE CONN AND PATH
    u8  saddr[4];
    u8  daddr[4];
    u8  mac[ETH_ALEN];
    u8  gw[ETH_ALEN];
    u16 eType;
    u8  iVersion;
    u8  iTOS;
    u64 reserved2;
    u64 reserved3;
} xsock_path_s;

// EXPECTED SIZE
#define XSOCK_CONN_SIZE (CACHE_LINE_SIZE + XSOCK_PATHS_N*XSOCK_PATH_SIZE)

typedef struct xsock_conn_s {
    u64 pid;
    u64 remaining;
    u64 _align[6];
    xsock_path_s paths[XSOCK_PATHS_N];
} xsock_conn_s;

typedef struct xsock_cfg_path_s {
    char itfc[IFNAMSIZ];
    u8 mac[ETH_ALEN];
    u8 gw[ETH_ALEN];
    u8 addr[4];
    u16 port;
    uint pkts; // TOTAL DE PACOTES A CADA CIRCULADA
} xsock_cfg_path_s;

typedef struct xsock_cfg_conn_s {
    xsock_cfg_path_s clt[XSOCK_PATHS_N];
    xsock_cfg_path_s srv[XSOCK_PATHS_N];
} xsock_cfg_conn_s;

static net_device_s* xdev;
#define CONN_ID(conn) ((uint)((conn) - conns))
static xsock_conn_s conns[XSOCK_CONNS_N];

static const xsock_cfg_conn_s cfg = {
    .clt = {
        { .pkts = XCONF_XSOCK_CLT_PATH_0_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_0_ITFC, .mac = XCONF_XSOCK_CLT_PATH_0_MAC, .gw = XCONF_XSOCK_CLT_PATH_0_GW, .addr = {XCONF_XSOCK_CLT_PATH_0_ADDR_0,XCONF_XSOCK_CLT_PATH_0_ADDR_1,XCONF_XSOCK_CLT_PATH_0_ADDR_2,XCONF_XSOCK_CLT_PATH_0_ADDR_3}, .port = XCONF_XSOCK_CLT_PATH_0_PORT, },
#if XSOCK_PATHS_N > 1
        { .pkts = XCONF_XSOCK_CLT_PATH_1_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_1_ITFC, .mac = XCONF_XSOCK_CLT_PATH_1_MAC, .gw = XCONF_XSOCK_CLT_PATH_1_GW, .addr = {XCONF_XSOCK_CLT_PATH_1_ADDR_0,XCONF_XSOCK_CLT_PATH_1_ADDR_1,XCONF_XSOCK_CLT_PATH_1_ADDR_2,XCONF_XSOCK_CLT_PATH_1_ADDR_3}, .port = XCONF_XSOCK_CLT_PATH_1_PORT, },
#if XSOCK_PATHS_N > 2
        { .pkts = XCONF_XSOCK_CLT_PATH_2_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_2_ITFC, .mac = XCONF_XSOCK_CLT_PATH_2_MAC, .gw = XCONF_XSOCK_CLT_PATH_2_GW, .addr = {XCONF_XSOCK_CLT_PATH_2_ADDR_0,XCONF_XSOCK_CLT_PATH_2_ADDR_1,XCONF_XSOCK_CLT_PATH_2_ADDR_2,XCONF_XSOCK_CLT_PATH_2_ADDR_3}, .port = XCONF_XSOCK_CLT_PATH_2_PORT, },
#if XSOCK_PATHS_N > 3
        { .pkts = XCONF_XSOCK_CLT_PATH_3_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_3_ITFC, .mac = XCONF_XSOCK_CLT_PATH_3_MAC, .gw = XCONF_XSOCK_CLT_PATH_3_GW, .addr = {XCONF_XSOCK_CLT_PATH_3_ADDR_0,XCONF_XSOCK_CLT_PATH_3_ADDR_1,XCONF_XSOCK_CLT_PATH_3_ADDR_2,XCONF_XSOCK_CLT_PATH_3_ADDR_3}, .port = XCONF_XSOCK_CLT_PATH_3_PORT, },
#endif
#endif
#endif
    },
    .srv = {
        { .pkts = XCONF_XSOCK_SRV_PATH_0_PKTS, .itfc = XCONF_XSOCK_SRV_PATH_0_ITFC, .mac = XCONF_XSOCK_SRV_PATH_0_MAC, .gw = XCONF_XSOCK_SRV_PATH_0_GW, .addr = {XCONF_XSOCK_SRV_PATH_0_ADDR_0,XCONF_XSOCK_SRV_PATH_0_ADDR_1,XCONF_XSOCK_SRV_PATH_0_ADDR_2,XCONF_XSOCK_SRV_PATH_0_ADDR_3}, .port = PORT(1, 0), },
#if XSOCK_PATHS_N > 1
        { .pkts = XCONF_XSOCK_SRV_PATH_1_PKTS, .itfc = XCONF_XSOCK_SRV_PATH_1_ITFC, .mac = XCONF_XSOCK_SRV_PATH_1_MAC, .gw = XCONF_XSOCK_SRV_PATH_1_GW, .addr = {XCONF_XSOCK_SRV_PATH_1_ADDR_0,XCONF_XSOCK_SRV_PATH_1_ADDR_1,XCONF_XSOCK_SRV_PATH_1_ADDR_2,XCONF_XSOCK_SRV_PATH_1_ADDR_3}, .port = PORT(1, 1), },
#if XSOCK_PATHS_N > 2
        { .pkts = XCONF_XSOCK_SRV_PATH_2_PKTS, .itfc = XCONF_XSOCK_SRV_PATH_2_ITFC, .mac = XCONF_XSOCK_SRV_PATH_2_MAC, .gw = XCONF_XSOCK_SRV_PATH_2_GW, .addr = {XCONF_XSOCK_SRV_PATH_2_ADDR_0,XCONF_XSOCK_SRV_PATH_2_ADDR_1,XCONF_XSOCK_SRV_PATH_2_ADDR_2,XCONF_XSOCK_SRV_PATH_2_ADDR_3}, .port = PORT(1, 2), },
#if XSOCK_PATHS_N > 3
        { .pkts = XCONF_XSOCK_SRV_PATH_3_PKTS, .itfc = XCONF_XSOCK_SRV_PATH_3_ITFC, .mac = XCONF_XSOCK_SRV_PATH_3_MAC, .gw = XCONF_XSOCK_SRV_PATH_3_GW, .addr = {XCONF_XSOCK_SRV_PATH_3_ADDR_0,XCONF_XSOCK_SRV_PATH_3_ADDR_1,XCONF_XSOCK_SRV_PATH_3_ADDR_2,XCONF_XSOCK_SRV_PATH_3_ADDR_3}, .port = PORT(1, 3), },
#endif
#endif
#endif
    }
};

static u16 xsock_crypto_encode (void* restrict data, uint size) {

    (void)data;
    (void)size;

    return size;
}

static u16 xsock_crypto_decode (void* restrict data, uint size) {

    (void)data;
    (void)size;

    return size;
}

static void xsock_conn_flows_update (xsock_conn_s* const conn) {

    // TODO: FIXME:

    printk("XSOCK: CONN %u: FLOWS UPDATED: PID %llu REMAINING %llu\n",
        CONN_ID(conn), (uintll)conn->pid, (uintll)conn->remaining);
}

static rx_handler_result_t xsock_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    // TODO: FIXME: DESCOBRIR O QUE CAUSA TANTOS SKBS NAO LINEARES AQUI
    // TODO: FIXME: pskb vs skb??? sera que vai te rque fazer skb_copy() e depois *pskb = skb ?
    // e aí faz ou não kfree_skb()?
    if (skb_linearize(skb))
        goto drop;

    xsock_wire_s* const wire = PTR(skb->data) + sizeof(wire->ip) + sizeof(wire->udp) - sizeof(xsock_wire_s);

    // IDENTIFY CONN AND PATH IDS FROM SERVER PORT
#if XSOCK_SERVER
    const uint port = BE16(wire->udp.dst);
#else
    const uint port = BE16(wire->udp.src);
#endif
    const uint cid = PORT_CID(port);
    const uint pid = PORT_PID(port);

    // CONFIRM PACKET SIZE
    // CONFIRM THIS IS ETHERNET/IPV4/UDP
    // VALIDATE CONN ID
    // VALIDATE PATH ID
    if ((PTR(wire) + sizeof(xsock_wire_s)) > SKB_TAIL(skb)
     || wire->eth.type    != BE16(ETH_P_IP)
     || wire->ip.version  != 0x45
     || wire->ip.protocol != IPPROTO_UDP
     || cid >= XSOCK_CONNS_N
     || pid >= XSOCK_PATHS_N
    )
        return RX_HANDLER_PASS;

    xsock_conn_s* const conn = &conns[cid];

    // THE PAYLOAD IS JUST AFTER OUR ENCAPSULATION
    void* const payload = PTR(wire) + sizeof(xsock_wire_s);
    // THE PAYLOAD SIZE IS EVERYTHING EXCEPT OUR ENCAPSULATION
    const uint payloadSize = BE16(wire->ip.size) - sizeof(wire->ip) - sizeof(wire->udp);

    // DROP INCOMPLETE PAYLOADS
    if ((payload + payloadSize) > SKB_TAIL(skb))
        goto drop;

    // DECRYPT AND CONFIRM INTEGRITY AND AUTHENTICITY
    if (xsock_crypto_decode(payload, payloadSize) != wire->ip.hash)
        goto drop;

    xsock_path_s* const path = &conn->paths[pid];

    // DETECT AND UPDATE PATH AVAILABILITY
    if (unlikely(!(path->flags &  XSOCK_PATH_F_UP_AUTO))) {
                   path->flags |= XSOCK_PATH_F_UP_AUTO; // TODO: FIXME: IMPLEMENTAR E USAR ISSO
        xsock_conn_flows_update(conn);
    }
#if XSOCK_SERVER
    // DETECT AND UPDATE PATH CHANGES
    net_device_s* const itfc = skb->dev;

    // NOTE: O SERVER NÃO PODE RECEBER ALEATORIAMENTE COM  UM MESMO IP EM MAIS DE UMA INTERACE, SENÃO VAI FICAR TROCANDO TODA HORA AQUI
    const u64 hash = (u64)(uintptr_t)itfc
      + (*(u64*)wire->eth.dst) // VAI PEGAR UM PEDAÇO DO eSrc
      + (*(u64*)wire->eth.src) // VAI PEGAR O eType
      + (*(u64*)wire->ip.src) // VAI PEGAR O iDst
      + (       wire->udp.src)
    ;

    if (unlikely(path->hash != hash)) {
                 path->hash =  hash;

        if (path->flags & XSOCK_PATH_F_ITFC_LEARN) // NOTE: SE CHEGOU ATÉ AQUI ENTÃO É UMA INTERFACE JÁ HOOKADA
            path->itfc = itfc;
        if (path->flags & XSOCK_PATH_F_MAC_LEARN)
            memcpy(path->mac, wire->eth.dst, ETH_ALEN);
        if (path->flags & XSOCK_PATH_F_GW_LEARN)
            memcpy(path->gw, wire->eth.src, ETH_ALEN);
        if (path->flags & XSOCK_PATH_F_SADDR_LEARN)
            memcpy(path->saddr, wire->ip.dst, 4);
        if (path->flags & XSOCK_PATH_F_DADDR_LEARN)
            memcpy(path->daddr, wire->ip.src, 4);
        if (path->flags & XSOCK_PATH_F_DPORT_LEARN)
            path->dport = wire->udp.src;

        printk("XSOCK: CONN %u: PATH %u: UPDATED WITH HASH 0x%016llX ITFC %s\n"
            " SRC %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n"
            " DST %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n",
            cid, pid, (uintll)path->hash, path->itfc->name,
            _MAC(path->mac), _IP4(path->saddr), BE16(path->sport),
            _MAC(path->gw),  _IP4(path->daddr), BE16(path->dport));
    }
#endif

    // DESENCAPSULA
    skb->ip_summed = CHECKSUM_NONE; // CHECKSUM_UNNECESSARY?
    skb->mac_len   = 0;
    skb->dev       = xdev;

    return RX_HANDLER_ANOTHER;

drop:
    kfree_skb(skb);

    *pskb = NULL;

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xsock_dev_start_xmit (sk_buff_s* const skb, net_device_s* const dev) {

    if (skb_linearize(skb))
        goto drop;

    xsock_wire_s* const wire = PTR(skb->data) + sizeof(wire->ip) + sizeof(wire->tcp) - sizeof(xsock_wire_s);

    if (PTR(&wire->eth) < PTR(skb->head))
        goto drop;

#if XSOCK_SERVER
    const uint cid = wire->ip.dst[3];
#else
    const uint cid = wire->ip.src[3];
#endif
    if (cid >= XSOCK_CONNS_N)
        goto drop;

    xsock_conn_s* const conn = &conns[cid];

    // CHOOSE PATH
    // ENVIA flowPackets, E AÍ AVANCA flowShift
    if (conn->remaining == 0)
        conn->remaining = conn->paths[(++(conn->pid)) % XSOCK_PATHS_N].pkts;
    else
        conn->remaining--;

    xsock_path_s* const path = &conn->paths[conn->pid];

    // THE PAYLOAD IS JUST AFTER OUR ENCAPSULATION
    void* const payload = PTR(wire) + sizeof(xsock_wire_s);
    // THE PAYLOAD SIZE IS EVERYTHING EXCEPT OUR ENCAPSULATION
    const uint size = BE16(wire->ip.size) - sizeof(wire->ip) - sizeof(wire->tcp);

    // RE-ENCAPSULATE, ENCRYPT AND AUTHENTIFY
    wire->ip.hash = xsock_crypto_encode(payload, size);
    wire->udp.size  = BE16(sizeof(wire->udp) + size);
    wire->ip.cksum = ip_fast_csum(PTR(&wire->ip), 5);

    skb->data             = PTR(&wire->eth);
    skb->mac_header       = PTR(&wire->eth) - PTR(skb->head);
    skb->network_header   = PTR(&wire->ip)  - PTR(skb->head);
    skb->transport_header = PTR(&wire->udp) - PTR(skb->head);
    skb->len              = ETH_HLEN + size;
    skb->mac_len          = ETH_HLEN;
    skb->protocol         = BE16(ETH_P_IP);
    skb->ip_summed        = CHECKSUM_NONE; // CHECKSUM_UNNECESSARY?

    // TODO: SE XSOCK_PATH_F_UP_ITFC FOR TRUE, ENTAO wire->itfc JÁ É TRUE
    // TODO: FIXME: CONSOLIDAR TODOS ESSES CHECKS EM UMA COISA SO TODA VEZ QUE ALTERAR ALGUM DELES
    if (!(FLAGS_IS_UP(path->flags) && path->itfc && path->itfc->flags & IFF_UP))
        goto drop;

    // TODO: AO TROCAR TEM QUE DAR dev_put(skb->dev) ?
    skb->dev = path->itfc;

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
    dev_queue_xmit(skb);

    return NETDEV_TX_OK;

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xsock_dev_up (net_device_s* const dev) {

    return 0;
}

static int xsock_dev_down (net_device_s* const dev) {

    return 0;
}

static int xsock_dev_header_create (sk_buff_s *skb, net_device_s *dev, unsigned short type, const void *daddr, const void *saddr, uint len) {

    return 0;
}

static const header_ops_s xsockHeaderOps = {
    .create = xsock_dev_header_create,
};

static const net_device_ops_s xsockDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  xsock_dev_up,
    .ndo_stop             =  xsock_dev_down,
    .ndo_start_xmit       =  xsock_dev_start_xmit,
    .ndo_set_mac_address  =  NULL,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void xsock_dev_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xsockDevOps;
    dev->header_ops      = &xsockHeaderOps;
    dev->type            = ARPHRD_NONE;
    dev->addr_len        = 0;
    dev->hard_header_len = ETH_HLEN;
    dev->min_header_len  = ETH_HLEN;
    dev->min_mtu         = ETH_MIN_MTU;
    dev->max_mtu         = ETH_MAX_MTU;
    dev->mtu             = ETH_MAX_MTU; // ETH_DATA_LEN
    dev->tx_queue_len    = 0; // DEFAULT_TX_QUEUE_LEN
    dev->flags           = IFF_NOARP; // IFF_BROADCAST | IFF_MULTICAST
    dev->priv_flags      = IFF_NO_QUEUE
                         | IFF_LIVE_ADDR_CHANGE
                         | IFF_LIVE_RENAME_OK
                         | IFF_NO_RX_HANDLER
        ;
}

static void xsock_path_init (xsock_conn_s* const restrict conn, const uint cid, xsock_path_s* const restrict path, const uint pid, const xsock_cfg_conn_s* const restrict cfg) {

#if XSOCK_SERVER
    const xsock_cfg_path_s* const peer = &cfg->clt[pid];
    const xsock_cfg_path_s* const this = &cfg->srv[pid];
#else
    const xsock_cfg_path_s* const this = &cfg->clt[pid];
    const xsock_cfg_path_s* const peer = &cfg->srv[pid];
#endif

    printk("XSOCK: CONN %u: PATH %u: INITIALIZING WITH PKTS %u ITFC %s"
        " %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u ->"
        " %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n",
        cid, pid, this->pkts, this->itfc,
        _MAC(this->mac), _IP4(this->addr), this->port,
        _MAC(this->gw),  _IP4(peer->addr), peer->port
    );

    path->flags =
          (XSOCK_PATH_F_UP          * !0)
        | (XSOCK_PATH_F_UP_AUTO     * !0)
#if XSOCK_SERVER
        | (XSOCK_PATH_F_ITFC_LEARN  * !0)
        | (XSOCK_PATH_F_MAC_LEARN   * !0)
        | (XSOCK_PATH_F_GW_LEARN    * !0)
        | (XSOCK_PATH_F_SADDR_LEARN * !0)
        | (XSOCK_PATH_F_DADDR_LEARN * !0)
        | (XSOCK_PATH_F_DPORT_LEARN * !0)
#endif
        ;
    path->itfc       = NULL;
#if XSOCK_SERVER
    path->hash       = 0;
#else
    path->reserved2  = 0;
#endif
    path->pkts       = this->pkts;
    path->sport      = BE16(this->port);
    path->dport      = BE16(peer->port);

    memcpy(path->mac, this->mac, ETH_ALEN);
    memcpy(path->gw,  this->gw,  ETH_ALEN);

    memcpy(path->saddr, this->addr, 4);
    memcpy(path->daddr, peer->addr, 4);

    net_device_s* const itfc = dev_get_by_name(&init_net, this->itfc);

    if (itfc) {

        rtnl_lock();

        // HOOK INTERFACE
        if (rcu_dereference(itfc->rx_handler) != xsock_in) {
            // NOT HOOKED YET
            if (!netdev_rx_handler_register(itfc, xsock_in, NULL)) {
                // HOOK SUCCESS
                // NOTE: ISSO É PARA QUE POSSA DAR FORWARD NOS PACOTES
                // NOTE: A INTERFACE JA TEM O ETH_HLEN
                itfc->hard_header_len += sizeof(xsock_path_s) - ETH_HLEN;
                itfc->min_header_len  += sizeof(xsock_path_s) - ETH_HLEN;
                //
                path->itfc = itfc;
            }
        } else // ALREADY HOOKED
            path->itfc = itfc;

        rtnl_unlock();

        if (path->itfc) { // TODO:
            path->flags |= XSOCK_PATH_F_UP_ITFC;
        } else { // TODO: LEMBRAR O NOME ENTÃO - APONTAR PARA O CONFIG?
            printk("XSOCK: CONN %u: PATH %u: INTERFACE NOT HOOKED\n", cid, pid);
            dev_put(itfc);
        }
    } else
        printk("XSOCK: CONN %u: PATH %u: INTERFACE NOT FOUND\n", cid, pid);
}

static void xsock_conn_init (const xsock_cfg_conn_s* const cfg, xsock_conn_s* const conn, const uint cid) {

    printk("XSOCK: CONN %u: INITIALIZING\n", cid);

    // INITIALIZE IT
    conn->remaining = 0;
    conn->pid       = 0;
    // INITIALIZE ITS PATHS
    foreach (pid, XSOCK_PATHS_N)
        xsock_path_init(conn, cid, &conn->paths[pid], pid, cfg);
    // INITIALIZE ITS FLOWS
    xsock_conn_flows_update(conn);
}

static int __init xsock_init(void) {

#if XSOCK_SERVER
    printk("XSOCK: SERVER INIT\n");
#else
    printk("XSOCK: CLIENT INIT\n");
#endif

    BUILD_BUG_ON(sizeof(struct xsock_wire_eth_s) != ETH_HLEN);
    BUILD_BUG_ON(sizeof(struct xsock_wire_ip_s) != sizeof(struct iphdr));
    BUILD_BUG_ON(sizeof(struct xsock_wire_tcp_s) != sizeof(struct tcphdr));
    BUILD_BUG_ON(sizeof(struct xsock_wire_udp_s) != sizeof(struct xsock_wire_tcp_s));

    BUILD_BUG_ON(sizeof(xsock_wire_s) != XSOCK_WIRE_SIZE);
    BUILD_BUG_ON(sizeof(xsock_path_s) != XSOCK_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xsock_conn_s) != XSOCK_CONN_SIZE);

    // CREATE THE VIRTUAL INTERFACE
    net_device_s* const dev = alloc_netdev(0, "xsock", NET_NAME_USER, xsock_dev_setup);

    if (!dev) {
        printk("XSOCK: CREATE FAILED - COULD NOT ALLOCATE\n");
        return -1;
    }

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(dev)) {
        printk("XSOCK: CREATE FAILED - COULD NOT REGISTER\n");
        free_netdev(dev);
        return -1;
    }

    xdev = dev;

    // INITIALIZE CONNS
    foreach (cid, ARRAY_COUNT(conns))
        xsock_conn_init(&cfg, &conns[cid], cid);

    return 0;
}

static void __exit xsock_exit(void) {

    printk("XSOCK: EXIT\n");

    if (xdev) {
        unregister_netdev(xdev);
        free_netdev(xdev);
    }
}

module_init(xsock_init);
module_exit(xsock_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XSOCK");
MODULE_VERSION("0.1");


/*
TODO: RETIRAR TAIS PORTAS DOS EPHEMERAL PORTS


TODO: CORRIGIR O XGW
no in
if (skb->len <= XSOCK_PATH_SIZE_WIRE

NO IN
e no transmit
o header nao pode ser CONST!!!
*/