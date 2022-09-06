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

#define XSOCK_PATHS_N XCONF_XSOCK_PATHS_N

#define XSOCK_SERVER      XCONF_XSOCK_SERVER_IS
#define XSOCK_SERVER_PORT XCONF_XSOCK_SERVER_PORT

#if XSOCK_SERVER
#define XSOCK_NODES_N XCONF_XSOCK_NODES_N
#else
#define XSOCK_NODE_ID XCONF_XSOCK_NODE_ID
#endif

#if ! (1 <= XSOCK_PATHS_N && XSOCK_PATHS_N <= 4)
#error "BAD XSOCK_PATHS_N"
#endif

#if ! (1 <= XSOCK_SERVER_PORT && XSOCK_SERVER_PORT <= 0xFFFF)
#error "BAD XSOCK_SERVER_PORT"
#endif

#if XSOCK_SERVER
#if ! (1 <= XSOCK_NODES_N && XSOCK_NODES_N <= 0xFFFF)
#error "BAD XSOCK_NODES_N"
#endif
#elif ! (0 <= XSOCK_NODE_ID && XSOCK_NODE_ID <= 0xFFFF)
#error "BAD XSOCK_NODE_ID"
#endif

//
#define PORT(nid, pid) (XSOCK_SERVER_PORT + (nid)*10 + (pid))
// WILL UNSIGNED OVERFLOW IF LOWER
#define PORT_NID(port) (((port) - XSOCK_SERVER_PORT) / 10)
#define PORT_PID(port) (((port) - XSOCK_SERVER_PORT) % 10)

//
#if XSOCK_SERVER && PORT(XSOCK_NODES_N - 1, XSOCK_PATHS_N - 1) > 0xFFFF
#error "BAD XSOCK_SERVER_PORT / XSOCK_NODES_N / XSOCK_PATHS_N"
#endif

#define XSOCK_PATH_F_UP                 0b0000000000000001U // ADMINISTRATIVELY
#define XSOCK_PATH_F_UP_AUTO            0b0000000000000010U // SE DER TIMEOUT VAI DESATIVAR ISSO
#define XSOCK_PATH_F_UP_ITFC            0b0000000000000100U // WATCH INTERFACE EVENTS AND SET THIS TODO: INICIALIZAR COMO 0 E CARREGAR ISSO NO DEVICE NOTIFIER
#if XSOCK_SERVER
#define XSOCK_PATH_F_ITFC_LEARN         0b0000000000001000U
#define XSOCK_PATH_F_E_SRC_LEARN        0b0000000000010000U
#define XSOCK_PATH_F_E_DST_LEARN        0b0000000000100000U
#define XSOCK_PATH_F_I_SRC_LEARN        0b0000000001000000U
#define XSOCK_PATH_F_I_DST_LEARN        0b0000000010000000U    // TODO: TIME DO ULTIMO RECEBIDO; DESATIVAR O PATH NO SERVIDOR SE NAO RECEBER NADA EM TANTO TEMPO
#define XSOCK_PATH_F_U_DST_LEARN        0b0000000100000000U
#endif

#define FLAGS_IS_UP(f) (((f) & (XSOCK_PATH_F_UP | XSOCK_PATH_F_UP_AUTO | XSOCK_PATH_F_UP_ITFC)) \
                            == (XSOCK_PATH_F_UP | XSOCK_PATH_F_UP_AUTO | XSOCK_PATH_F_UP_ITFC))

// EXPECTED SIZE
#define XSOCK_WIRE_SIZE CACHE_LINE_SIZE

#define WIRE_ETH(wire) PTR(&(wire)->eDst)
#define WIRE_IP(wire)  PTR(&(wire)->iVersion)
#define WIRE_UDP(wire) PTR(&(wire)->uSrc)

typedef struct xsock_wire_s {
    u8 _align[10];
#define ETH_HDR_SIZE 14
    u8  eDst[ETH_ALEN];
    u8  eSrc[ETH_ALEN];
    u16 eType;
#define IP4_HDR_SIZE 20
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iHash; // A CHECKSUM TO CONFIRM THE AUTHENTICITY OF THE PACKET
    u16 iFrag;
    u8  iTTL;
    u8  iProtocol;
    u16 iCksum;
    u8  iSrc[4];
    u8  iDst[4];
#define TCP_HDR_SIZE 20
    union {
        struct { // AS ORIGINAL TCP
            u16 tSrc;
            u16 tDst;
            u32 tSeq;
            u32 tAck;
            u16 tFlags;
            u16 tWindow;
            u16 tChecksum;
            u16 tUrgent;
        };
        struct { // AS FAKE UDP
            u16 uSrc;
            u16 uDst; // THE XSOCK_SERVER PORT WILL DETERMINE THE NODE AND PATH
            u16 uSize;
            u16 uCksum;
            u32 uAck;
            u16 uFlags;
            u16 uWindow;
            u32 uSeq;
        };
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
    u16 band;
    u16 uSrc;
    u16 uDst; // THE XSOCK_SERVER PORT WILL DETERMINE THE NODE AND PATH
    u8  iSrc[4];
    u8  iDst[4];
    u8  eDst[ETH_ALEN];
    u8  eSrc[ETH_ALEN];
    u16 eType;
    u16 reserved4;
    u64 reserved2;
    u64 reserved3;
} xsock_path_s;

#define XSOCK_FLOWS_N (2*CACHE_LINE_SIZE \
    - sizeof(u32)*2 \
    - sizeof(u16) \
    )

// EXPECTED SIZE
#define XSOCK_NODE_SIZE ((2 + XSOCK_PATHS_N)*CACHE_LINE_SIZE)

static net_device_s* xdev;

typedef struct xsock_node_s {
    u32 flowPackets; // O QUE USAR COMO FLOW REMAINING
    u32 flowRemaining; // QUANTOS PACOTES ENVIAR ATÉ AVANÇAR O FLOW SHIFT
    u16 flowShift; // SHIFTA TODOS OS FLOW IDS AO MESMO TEMPO, AO SELECIONAR O PATH
    u8  flows[XSOCK_FLOWS_N]; // MAPA FLOW ID -> PATH ID
    xsock_path_s paths[XSOCK_PATHS_N];
} xsock_node_s;

typedef struct xsock_cfg_path_s {
    char itfc[IFNAMSIZ];
    u8 mac[ETH_ALEN];
    u8 gw[ETH_ALEN];
    u8 addr[4];
    u16 port;
    uint band; // TOTAL DE PACOTES A CADA CIRCULADA
} xsock_cfg_path_s;

typedef struct xsock_cfg_node_srv_s {
    uint pkts;
    xsock_cfg_path_s paths[XSOCK_PATHS_N];
} xsock_cfg_node_side_s;

typedef struct xsock_cfg_node_s {
    uint id;
    xsock_cfg_node_side_s clt;
    xsock_cfg_node_side_s srv;
} xsock_cfg_node_s;

#if XSOCK_SERVER
#define NODE_ID(node) ((uint)((node) - nodes))
static xsock_node_s nodes[XSOCK_NODES_N];
#else
#define NODE_ID(node) XSOCK_NODE_ID
static xsock_node_s node[1];
#endif

static const xsock_cfg_node_s cfgNodes[] = {
#if (XSOCK_SERVER && XSOCK_NODES_N > 1) || XSOCK_NODE_ID == 1
    { .id = 1,
        .clt = { .pkts = XCONF_XSOCK_NODE_1_CLT_PKTS, .paths = {
            { .itfc = XCONF_XSOCK_NODE_1_CLT_PATH_0_ITFC, .band = XCONF_XSOCK_NODE_1_CLT_PATH_0_BAND, .mac = XCONF_XSOCK_NODE_1_CLT_PATH_0_MAC, .gw = XCONF_XSOCK_NODE_1_CLT_PATH_0_GW, .addr = {XCONF_XSOCK_NODE_1_CLT_PATH_0_ADDR_0,XCONF_XSOCK_NODE_1_CLT_PATH_0_ADDR_1,XCONF_XSOCK_NODE_1_CLT_PATH_0_ADDR_2,XCONF_XSOCK_NODE_1_CLT_PATH_0_ADDR_3}, .port = XCONF_XSOCK_NODE_1_CLT_PATH_0_PORT, },
#if XSOCK_PATHS_N > 1
            { .itfc = XCONF_XSOCK_NODE_1_CLT_PATH_1_ITFC, .band = XCONF_XSOCK_NODE_1_CLT_PATH_1_BAND, .mac = XCONF_XSOCK_NODE_1_CLT_PATH_1_MAC, .gw = XCONF_XSOCK_NODE_1_CLT_PATH_1_GW, .addr = {XCONF_XSOCK_NODE_1_CLT_PATH_1_ADDR_0,XCONF_XSOCK_NODE_1_CLT_PATH_1_ADDR_1,XCONF_XSOCK_NODE_1_CLT_PATH_1_ADDR_2,XCONF_XSOCK_NODE_1_CLT_PATH_1_ADDR_3}, .port = XCONF_XSOCK_NODE_1_CLT_PATH_1_PORT, },
#if XSOCK_PATHS_N > 2
            { .itfc = XCONF_XSOCK_NODE_1_CLT_PATH_2_ITFC, .band = XCONF_XSOCK_NODE_1_CLT_PATH_2_BAND, .mac = XCONF_XSOCK_NODE_1_CLT_PATH_2_MAC, .gw = XCONF_XSOCK_NODE_1_CLT_PATH_2_GW, .addr = {XCONF_XSOCK_NODE_1_CLT_PATH_2_ADDR_0,XCONF_XSOCK_NODE_1_CLT_PATH_2_ADDR_1,XCONF_XSOCK_NODE_1_CLT_PATH_2_ADDR_2,XCONF_XSOCK_NODE_1_CLT_PATH_2_ADDR_3}, .port = XCONF_XSOCK_NODE_1_CLT_PATH_2_PORT, },
#if XSOCK_PATHS_N > 3
            { .itfc = XCONF_XSOCK_NODE_1_CLT_PATH_3_ITFC, .band = XCONF_XSOCK_NODE_1_CLT_PATH_3_BAND, .mac = XCONF_XSOCK_NODE_1_CLT_PATH_3_MAC, .gw = XCONF_XSOCK_NODE_1_CLT_PATH_3_GW, .addr = {XCONF_XSOCK_NODE_1_CLT_PATH_3_ADDR_0,XCONF_XSOCK_NODE_1_CLT_PATH_3_ADDR_1,XCONF_XSOCK_NODE_1_CLT_PATH_3_ADDR_2,XCONF_XSOCK_NODE_1_CLT_PATH_3_ADDR_3}, .port = XCONF_XSOCK_NODE_1_CLT_PATH_3_PORT, },
#endif
#endif
#endif
        }},
        .srv = { .pkts = XCONF_XSOCK_NODE_1_SRV_PKTS, .paths = {
            { .itfc = XCONF_XSOCK_NODE_1_SRV_PATH_0_ITFC, .band = XCONF_XSOCK_NODE_1_SRV_PATH_0_BAND, .mac = XCONF_XSOCK_NODE_1_SRV_PATH_0_MAC, .gw = XCONF_XSOCK_NODE_1_SRV_PATH_0_GW, .addr = {XCONF_XSOCK_NODE_1_SRV_PATH_0_ADDR_0,XCONF_XSOCK_NODE_1_SRV_PATH_0_ADDR_1,XCONF_XSOCK_NODE_1_SRV_PATH_0_ADDR_2,XCONF_XSOCK_NODE_1_SRV_PATH_0_ADDR_3}, .port = PORT(1, 0), },
#if XSOCK_PATHS_N > 1
            { .itfc = XCONF_XSOCK_NODE_1_SRV_PATH_1_ITFC, .band = XCONF_XSOCK_NODE_1_SRV_PATH_1_BAND, .mac = XCONF_XSOCK_NODE_1_SRV_PATH_1_MAC, .gw = XCONF_XSOCK_NODE_1_SRV_PATH_1_GW, .addr = {XCONF_XSOCK_NODE_1_SRV_PATH_1_ADDR_0,XCONF_XSOCK_NODE_1_SRV_PATH_1_ADDR_1,XCONF_XSOCK_NODE_1_SRV_PATH_1_ADDR_2,XCONF_XSOCK_NODE_1_SRV_PATH_1_ADDR_3}, .port = PORT(1, 1), },
#if XSOCK_PATHS_N > 2
            { .itfc = XCONF_XSOCK_NODE_1_SRV_PATH_2_ITFC, .band = XCONF_XSOCK_NODE_1_SRV_PATH_2_BAND, .mac = XCONF_XSOCK_NODE_1_SRV_PATH_2_MAC, .gw = XCONF_XSOCK_NODE_1_SRV_PATH_2_GW, .addr = {XCONF_XSOCK_NODE_1_SRV_PATH_2_ADDR_0,XCONF_XSOCK_NODE_1_SRV_PATH_2_ADDR_1,XCONF_XSOCK_NODE_1_SRV_PATH_2_ADDR_2,XCONF_XSOCK_NODE_1_SRV_PATH_2_ADDR_3}, .port = PORT(1, 2), },
#if XSOCK_PATHS_N > 3
            { .itfc = XCONF_XSOCK_NODE_1_SRV_PATH_3_ITFC, .band = XCONF_XSOCK_NODE_1_SRV_PATH_3_BAND, .mac = XCONF_XSOCK_NODE_1_SRV_PATH_3_MAC, .gw = XCONF_XSOCK_NODE_1_SRV_PATH_3_GW, .addr = {XCONF_XSOCK_NODE_1_SRV_PATH_3_ADDR_0,XCONF_XSOCK_NODE_1_SRV_PATH_3_ADDR_1,XCONF_XSOCK_NODE_1_SRV_PATH_3_ADDR_2,XCONF_XSOCK_NODE_1_SRV_PATH_3_ADDR_3}, .port = PORT(1, 3), },
#endif
#endif
#endif
        }}
    },
#endif
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

static void xsock_node_flows_update (xsock_node_s* const node) {

    uint total = 0;
    uint maiorB = 0;
    uint maiorP = 0;

    foreach (pid, XSOCK_PATHS_N) {
        const uint b = FLAGS_IS_UP(node->paths[pid].flags) * node->paths[pid].band;
        // CALCULA O TOTAL
        total += b;
        // LEMBRA O PATH COM MAIOR BANDWIDTH
        // LEMBRA O BANDWIDTH DELE
        if (maiorB < b) {
            maiorB = b;
            maiorP = pid;
        }
    }

    u8* flow = node->flows;
    uint pid = maiorP;

    if (total) {
        do {
            for (uint q = ( (uintll)XSOCK_FLOWS_N * FLAGS_IS_UP(node->paths[pid].flags) * node->paths[pid].band
                ) / total; q; q--)
                *flow++ = pid;
            pid = (pid + 1) % XSOCK_PATHS_N;
        } while (flow != &node->flows[XSOCK_FLOWS_N] && pid != maiorP);
    }

    // O QUE SOBRAR DEIXA COM O MAIOR PATH
    while (flow != &node->flows[XSOCK_FLOWS_N])
          *flow++ = pid;

    // PRINT IT
    char flowsStr[XSOCK_FLOWS_N + 1];

    foreach (fid, XSOCK_FLOWS_N)
        flowsStr[fid] = '0' + node->flows[fid];
    flowsStr[XSOCK_FLOWS_N] = '\0';

    printk("XSOCK: NODE %u: FLOWS UPDATED: PACKETS %u REMAINING %u FLOWS %s\n",
        NODE_ID(node), node->flowPackets, node->flowRemaining, flowsStr);
}

static rx_handler_result_t xsock_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    // TODO: FIXME: DESCOBRIR O QUE CAUSA TANTOS SKBS NAO LINEARES AQUI
    // TODO: FIXME: pskb vs skb??? sera que vai te rque fazer skb_copy() e depois *pskb = skb ?
    // e aí faz ou não kfree_skb()?
    if (skb_linearize(skb))
        goto drop;

    xsock_wire_s* const wire = PTR(skb->data) + IP4_HDR_SIZE + TCP_HDR_SIZE - sizeof(xsock_wire_s);

    // IDENTIFY NODE AND PATH IDS FROM SERVER PORT
#if XSOCK_SERVER
    const uint port = BE16(wire->uDst);
#else
    const uint port = BE16(wire->uSrc);
#endif
    const uint nid = PORT_NID(port);
    const uint pid = PORT_PID(port);

    // CONFIRM PACKET SIZE
    // CONFIRM THIS IS ETHERNET/IPV4/UDP
    // VALIDATE NODE ID
    // VALIDATE PATH ID
    if ((PTR(wire) + sizeof(xsock_wire_s)) > SKB_TAIL(skb)
     || wire->eType     != BE16(ETH_P_IP)
     || wire->iVersion  != 0x45
     || wire->iProtocol != IPPROTO_UDP
#if XSOCK_SERVER
     || nid >= XSOCK_NODES_N
#else
     || nid != XSOCK_NODE_ID
#endif
     || pid >= XSOCK_PATHS_N
    )
        return RX_HANDLER_PASS;

#if XSOCK_SERVER
    xsock_node_s* const node = &nodes[nid];
#endif

    // THE PAYLOAD IS JUST AFTER OUR ENCAPSULATION
    void* const payload = PTR(wire) + sizeof(xsock_wire_s);
    // THE PAYLOAD SIZE IS EVERYTHING EXCEPT OUR ENCAPSULATION
    const uint payloadSize = BE16(wire->iSize) - IP4_HDR_SIZE - TCP_HDR_SIZE;

    // DROP EMPTY/INCOMPLETE PAYLOADS
    if ((payloadSize == 0) || (payload + payloadSize) > SKB_TAIL(skb))
        goto drop;

    // DECRYPT AND CONFIRM AUTHENTICITY
    if (xsock_crypto_decode(payload, payloadSize) != wire->iHash)
        goto drop;

    xsock_path_s* const path = &node->paths[pid];

    // DETECT AND UPDATE PATH AVAILABILITY
    if (unlikely(!(path->flags & XSOCK_PATH_F_UP_AUTO))) {
        path->flags |= XSOCK_PATH_F_UP_AUTO; // TODO: FIXME: IMPLEMENTAR E USAR ISSO
        xsock_node_flows_update(node);
    }
#if XSOCK_SERVER
    // DETECT AND UPDATE PATH CHANGES
    net_device_s* const itfc = skb->dev;

    // NOTE: O SERVER NÃO PODE RECEBER ALEATORIAMENTE COM  UM MESMO IP EM MAIS DE UMA INTERACE, SENÃO VAI FICAR TROCANDO TODA HORA AQUI
    const u64 hash = (u64)(uintptr_t)itfc
      + (*(u64*)wire->eDst) // VAI PEGAR UM PEDAÇO DO eSrc
      + (*(u64*)wire->eSrc) // VAI PEGAR O eType
      + (*(u64*)wire->iSrc) // VAI PEGAR O iDst
      + (       wire->uSrc)
    ;

    if (unlikely(path->hash != hash)) {
                 path->hash = hash;

        if (path->flags & XSOCK_PATH_F_ITFC_LEARN) // NOTE: SE CHEGOU ATÉ AQUI ENTÃO É UMA INTERFACE JÁ HOOKADA
            path->itfc = itfc;
        if (path->flags & XSOCK_PATH_F_E_SRC_LEARN)
            memcpy(path->eSrc, wire->eDst, ETH_ALEN);
        if (path->flags & XSOCK_PATH_F_E_DST_LEARN)
            memcpy(path->eDst, wire->eSrc, ETH_ALEN);
        if (path->flags & XSOCK_PATH_F_I_SRC_LEARN)
            memcpy(path->iSrc, wire->iDst, 4);
        if (path->flags & XSOCK_PATH_F_I_DST_LEARN)
            memcpy(path->iDst, wire->iSrc, 4);
        if (path->flags & XSOCK_PATH_F_U_DST_LEARN)
            path->uDst = wire->uSrc;

        printk("XSOCK: NODE %u: PATH %u: UPDATED WITH HASH 0x%016llX ITFC %s\n"
            " SRC %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n"
            " DST %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n",
            nid, pid, (uintll)path->hash, path->itfc->name,
            _MAC(path->eSrc), _IP4(path->iSrc), BE16(path->uSrc),
            _MAC(path->eDst), _IP4(path->iDst), BE16(path->uDst));
    }
#endif

    // NOTE: MAKE SURE WE DO THE EQUIVALENT OF TRIM
    // pskb_trim(skb, payloadSize);

    // DESENCAPSULA
    skb->ip_summed        = CHECKSUM_NONE; // CHECKSUM_UNNECESSARY?
    skb->mac_len          = 0;
    skb->len              = payloadSize;
    skb->data             = PTR(payload);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       =
    skb->network_header   =
    skb->transport_header = PTR(payload) - PTR(skb->head);
    skb->tail             = PTR(payload) - PTR(skb->head) + payloadSize;
#else
    skb->mac_header       =
    skb->network_header   =
    skb->transport_header = PTR(payload);
    skb->tail             = PTR(payload) + payloadSize;
#endif
    skb->dev              = xdev;
    skb->protocol         =
        (*(u8*)payload & 0b0100000U) ?
            BE16(ETH_P_IPV6) :
            BE16(ETH_P_IP);

    return RX_HANDLER_ANOTHER;

drop:
    kfree_skb(skb);

    *pskb = NULL;

    return RX_HANDLER_CONSUMED;
}

#if 0
#define V4_PROTO_SOURCE        0x00FF0000FFFFFFFFULL
#define V6_VERSION_FLOW_PROTO  0xF00FFFFF0000FF00ULL
#define V6_PORTS               0xFFFFFFFF00000000ULL
#else
#define V4_PROTO_SOURCE        0xFFFFFFFF0000FF00ULL
#define V6_VERSION_FLOW_PROTO  0x00FF0000FFFF0FF0ULL
#define V6_PORTS               0x00000000FFFFFFFFULL
#endif

static netdev_tx_t xsock_dev_start_xmit (sk_buff_s* const skb, net_device_s* const dev) {

    if (skb_linearize(skb))
        goto drop;

    xsock_wire_s* const wire = PTR(skb->data) + IP4_HDR_SIZE + TCP_HDR_SIZE - sizeof(xsock_wire_s);

    const uint nid = 0; // TODO: FIXME:

#if XSOCK_SERVER
    xsock_node_s* const node = &nodes[nid];
#endif

    if (PTR(wire) < PTR(skb->head) || skb->data_len)
        goto drop;

    // ENVIA flowPackets, E AÍ AVANCA flowShift
    if (node->flowRemaining == 0) {
        node->flowRemaining = node->flowPackets / XSOCK_FLOWS_N;
        node->flowShift++;
    } else
        node->flowRemaining--;

    // THE PAYLOAD IS JUST AFTER OUR ENCAPSULATION
    void* const payload = PTR(wire) + sizeof(xsock_wire_s);
    // THE PAYLOAD SIZE IS EVERYTHING EXCEPT OUR ENCAPSULATION
    const uint size = BE16(wire->iSize) - IP4_HDR_SIZE - TCP_HDR_SIZE;

    // CHOOSE PATH
    xsock_path_s* const path = &node->paths[(
            (skb->mark >= 30000) &&
            (skb->mark <  40000)
                ? // PATH BY MARK
                    skb->mark
                : // PATH BY FLOW
                    node->flows[( node->flowShift + (
                        (skb->mark >= 40000) &&
                        (skb->mark <  50000)
                            ? // FLOW BY MARK
                            skb->mark
                            : // FLOW BY HASH
                            (nid + wire->uSrc + wire->uDst)
                    )) % XSOCK_FLOWS_N]
        ) % XSOCK_PATHS_N];

    // RE-ENCAPSULATE, ENCRYPT AND AUTHENTIFY
    wire->iHash = xsock_crypto_encode(payload, size);
    wire->uSize  = BE16(TCP_HDR_SIZE + size);
    wire->iCksum = ip_fast_csum(WIRE_IP(wire), 5);

    skb->data             = WIRE_ETH(wire);
    skb->mac_header       = WIRE_ETH(wire) - PTR(skb->head);
    skb->network_header   = WIRE_IP(wire)  - PTR(skb->head);
    skb->transport_header = WIRE_UDP(wire) - PTR(skb->head);
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

static void xsock_path_init (xsock_node_s* const restrict node, const uint nid, xsock_path_s* const restrict path, const uint pid, const xsock_cfg_node_s* const restrict cfg) {

#if XSOCK_SERVER
    const xsock_cfg_path_s* const peer = &cfg->clt.paths[pid];
    const xsock_cfg_path_s* const this = &cfg->srv.paths[pid];
#else
    const xsock_cfg_path_s* const this = &cfg->clt.paths[pid];
    const xsock_cfg_path_s* const peer = &cfg->srv.paths[pid];
#endif

    printk("XSOCK: NODE %u: PATH %u: INITIALIZING WITH BAND %u ITFC %s"
        " %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u -> %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u %u\n",
        nid, pid, this->band, this->itfc,
        _MAC(this->mac), _IP4(this->addr), this->port,
        _MAC(this->gw),  _IP4(peer->addr), peer->port
    );

    path->flags =
          (XSOCK_PATH_F_UP          * !0)
        | (XSOCK_PATH_F_UP_AUTO     * !0)
#if XSOCK_SERVER
        | (XSOCK_PATH_F_ITFC_LEARN  * !0)
        | (XSOCK_PATH_F_E_SRC_LEARN * !0)
        | (XSOCK_PATH_F_E_DST_LEARN * !0)
        | (XSOCK_PATH_F_I_SRC_LEARN * !0)
        | (XSOCK_PATH_F_I_DST_LEARN * !0)
        | (XSOCK_PATH_F_U_DST_LEARN * !0)
#endif
        ;
    path->itfc       = NULL;
#if XSOCK_SERVER
    path->hash       = 0;
#else
    path->reserved2  = 0;
#endif
    path->band       = this->band;
    path->uSrc       = BE16(this->port);
    path->uDst       = BE16(peer->port);

    memcpy(path->eSrc, this->mac, ETH_ALEN);
    memcpy(path->eDst, this->gw,  ETH_ALEN);

    memcpy(path->iSrc, this->addr, 4);
    memcpy(path->iDst, peer->addr, 4);

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
            printk("XSOCK: NODE %u: PATH %u: INTERFACE NOT HOOKED\n", nid, pid);
            dev_put(itfc);
        }
    } else
        printk("XSOCK: NODE %u: PATH %u: INTERFACE NOT FOUND\n", nid, pid);
}

static void xsock_node_init (const xsock_cfg_node_s* const cfg) {

    const uint nid = cfg->id;
#if XSOCK_SERVER
    xsock_node_s* const node = &nodes[nid];
#endif
#if XSOCK_SERVER
    const xsock_cfg_node_side_s* const this = &cfg->srv;
#else
    const xsock_cfg_node_side_s* const this = &cfg->clt;
#endif

    printk("XSOCK: NODE %u: INITIALIZING WITH PKTS %u\n",
        nid, this->pkts);

    node->flowPackets   = this->pkts;
    node->flowRemaining = 0;
    node->flowShift     = 0;

    // INITIALIZE ITS PATHS
    foreach (pid, XSOCK_PATHS_N)
        xsock_path_init(node, nid, &node->paths[pid], pid, cfg);
    // INITIALIZE ITS FLOWS
    xsock_node_flows_update(node);
}

static int __init xsock_init(void) {

#if XSOCK_SERVER
    printk("XSOCK: SERVER INIT\n");
#else
    printk("XSOCK: CLIENT INIT\n");
#endif

    BUILD_BUG_ON(sizeof(xsock_wire_s) != XSOCK_WIRE_SIZE);
    BUILD_BUG_ON(sizeof(xsock_path_s) != XSOCK_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xsock_node_s) != XSOCK_NODE_SIZE);

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

    // INITIALIZE NODE(S)
#if XSOCK_SERVER
    memset(nodes, 0, sizeof(nodes));
#else
    memset(node, 0, sizeof(node));
#endif
    foreach (i, ARRAY_COUNT(cfgNodes))
        xsock_node_init(&cfgNodes[i]);

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
TODO: CORRIGIR O XGW
no in
if (skb->len <= XSOCK_PATH_SIZE_WIRE

NO IN
e no transmit
o header nao pode ser CONST!!!
*/