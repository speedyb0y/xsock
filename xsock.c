/*

    TODO: mixed HW and IP checksum settings.
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

#define SKB_DATA(skb) PTR((skb)->data)
#define SKB_HEAD(skb) PTR((skb)->head)
#define SKB_TAIL(skb) PTR(skb_tail_pointer(skb))

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif(c) else if(c)

#define foreach(i, t) for (uint i = 0; i != (t); i++)

#ifdef __BIG_ENDIAN
#define BE16(x) (x)
#define BE32(x) (x)
#define BE64(x) (x)
#else
#define BE16(x) ((u16)__builtin_bswap16((u16)(x)))
#define BE32(x) ((u32)__builtin_bswap32((u32)(x)))
#define BE64(x) ((u64)__builtin_bswap64((u64)(x)))
#endif

#define CACHE_LINE_SIZE 64

#define _MAC(x) BE16((x)[0]), BE16((x)[1]), BE16((x)[2])
#define _IP4(x) BE32(x)

#define XSOCK_SERVER      XCONF_XSOCK_SERVER_IS
#define XSOCK_PORT        XCONF_XSOCK_PORT
#define XSOCK_MARK        XCONF_XSOCK_MARK
#define XSOCK_HOSTS_N     XCONF_XSOCK_HOSTS_N
#define XSOCK_PATHS_N     XCONF_XSOCK_PATHS_N
#define XSOCK_HOST_ID     XCONF_XSOCK_HOST_ID

#if ! (1 <= XSOCK_PORT && XSOCK_PORT <= 0xFFFF)
#error "BAD XSOCK_PORT"
#endif

#if ! (1 <= XSOCK_HOSTS_N && XSOCK_HOSTS_N <= 254)
#error "BAD XSOCK_HOSTS_N"
#endif

#if ! (1 <= XSOCK_PATHS_N && XSOCK_PATHS_N <= 4)
#error "BAD XSOCK_PATHS_N"
#endif

// THE ON-WIRE SERVER PORT WILL DETERMINE THE HOST AND PATH
#define PORT(hid, pid) (XSOCK_PORT + (hid)*10 + (pid))
#define PORT_HID(port) (((uint)(port) - XSOCK_PORT) / 10)
#define PORT_PID(port) (((uint)(port) - XSOCK_PORT) % 10)

// O ULTIMO HOST E ULTIMO PATH TEM QUE DAR UMA PORTA VALIDA
#if PORT(XSOCK_HOSTS_N - 1, XSOCK_PATHS_N - 1) > 0xFFFF
#error "BAD XSOCK_PORT / XSOCK_HOSTS_N / XSOCK_PATHS_N"
#endif

// 0xFFFF + 1
#define XSOCK_CONNS_N 65536

#define ADDR_SRV 0xC0000000U // 192.0.0.0
#define ADDR_CLT 0xC0000001U // 192.0.0.1

#if XSOCK_SERVER
#define printk_host(msg, ...) printk("XSOCK: HOST: %u " msg, hid, ##__VA_ARGS__)
#else
#define printk_host(msg, ...) printk("XSOCK: " msg, ##__VA_ARGS__)
#endif

#ifdef __BIG_ENDIAN
#define XSOCK_WIRE_TCP_CWR 0b0000000010000000U
#define XSOCK_WIRE_TCP_ECE 0b0000000001000000U
#define XSOCK_WIRE_TCP_URG 0b0000000000100000U
#define XSOCK_WIRE_TCP_ACK 0b0000000000010000U
#define XSOCK_WIRE_TCP_PSH 0b0000000000001000U
#define XSOCK_WIRE_TCP_RST 0b0000000000000100U
#define XSOCK_WIRE_TCP_SYN 0b0000000000000010U
#define XSOCK_WIRE_TCP_FIN 0b0000000000000001U
#else
#define XSOCK_WIRE_TCP_CWR 0b1000000000000000U
#define XSOCK_WIRE_TCP_ECE 0b0100000000000000U
#define XSOCK_WIRE_TCP_URG 0b0010000000000000U
#define XSOCK_WIRE_TCP_ACK 0b0001000000000000U
#define XSOCK_WIRE_TCP_PSH 0b0000100000000000U
#define XSOCK_WIRE_TCP_RST 0b0000010000000000U
#define XSOCK_WIRE_TCP_SYN 0b0000001000000000U
#define XSOCK_WIRE_TCP_FIN 0b0000000100000000U
#endif

#define WIRE_ETH(wire)         PTR(&(wire)->eDst)
#define WIRE_IP(wire)          PTR(&(wire)->iVersionTOS)
#define WIRE_UDP(wire)         PTR(&(wire)->ports)
#define WIRE_UDP_PAYLOAD(wire) PTR(&(wire)->uPayload)

// EXPECTED SIZE
#define XSOCK_WIRE_SIZE 56

typedef struct xsock_wire_s {
    u16 _align;
    u16 eDst[ETH_ALEN/sizeof(u16)];
    u16 eSrc[ETH_ALEN/sizeof(u16)];
    u16 eType;
    u16 iVersionTOS;
    u16 iSize;
    u16 iCID; // CONNECTION ID (CLIENT SOURCE (EPHEMERAL) PORT)
    u16 iFrag;
    u8  iTTL;
    u8  iProtocol;
    u16 iChecksum;
    u32 iAddrs[2];
    u16 ports[2];
    union {
            u32 tSeq;
        struct {
            u16 uSize;
            u16 uChecksum;
        };
    };
    union {
        struct { // AS ORIGINAL TCP
            u32 tAck;
            u16 tFlags;
            u16 tWindow;
            u32 tSeq2; // CHECKSUM & URGENT
        };
            u16 uPayload[6]; // AS FAKE UDP
    };
} xsock_wire_s;

#define wire_hash(wire, ipSizeOrig) \
    ((wire_hash_t*)(WIRE_IP(wire) + (ipSizeOrig)))

typedef u32 wire_hash_t;

// EXPECTED SIZE
#define XSOCK_PATH_SIZE CACHE_LINE_SIZE

typedef struct xsock_path_s {
    net_device_s* itfc;
    u32 oBurst; // QUANTO TEMPO (EM JIFFIES) CONSIDERAR NOVOS PACOTES PARTES DO MESMO BURST E PORTANTO PERMANECER NESTE PATH
    u32 oPkts; // MÁXIMO DE PACOTES A ENVIAR ATÉ PASSAR PARA OUTRO PATH
    u16 oTime; // MÁXIMO DE TEMPO (EM SEGUNDOS) ATÉ PASSAR PARA OUTRO PATH
#if XSOCK_SERVER // TODO: FIXME: NO CLIENTE USAR ISSO TAMBÉM, MAS DE TEMPOS EM TEMPOS TENTAR RESTAURAR, E COM VALORES MENORES DE PKTS E TIME
    u16 cport;
    u16 iTimeout; // MÁXIMO DE TEMPO (EM SEGUNDOS) QUE PODE FICAR SEM RECEBER NADA E AINDA ASSIM CONSIDERAR COMO FUNCIONANDO
    u16 reserved0;
    u64 iActive; // ATÉ ESTE TIME (EM JIFFIES), CONSIDERA QUE A CONEXÃO ESTÁ ATIVA
    u64 iHash; // THE PATH HASH
#else
    u16 reserved0;
    u32 reserved1;
    u64 reserved2;
    u64 reserved3;
#endif
    u16 eDst[ETH_ALEN/sizeof(u16)];
    u16 eSrc[ETH_ALEN/sizeof(u16)];
    u16 eType;
    u16 iVersionTOS;
    u32 iAddrs[2];
} xsock_path_s;

// EXPECTED SIZE
#define XSOCK_CONN_SIZE 24

typedef struct xsock_conn_s {
    u32 pkts;
    u16 cdown;
    u16 pid;
    u64 burst; //
    u64 limit;
} xsock_conn_s;

typedef struct xsock_host_s {
    xsock_path_s paths[XSOCK_PATHS_N];
    xsock_conn_s conns[XSOCK_CONNS_N];
} xsock_host_s;

typedef struct xsock_cfg_path_s {
    char itfc[IFNAMSIZ];
    uint oBurst;
    uint oTime;
    uint oPkts;
    uint iTimeout;
    uint port;
    union { u8 mac[ETH_ALEN]; u16 eSrc[ETH_ALEN/sizeof(u16)]; };
    union { u8 gw [ETH_ALEN]; u16 eDst[ETH_ALEN/sizeof(u16)]; };
    union { u8 addr[4]; u32 addr32; };
} xsock_cfg_path_s;

typedef struct xsock_cfg_s {
    xsock_cfg_path_s clt[XSOCK_PATHS_N];
    xsock_cfg_path_s srv[XSOCK_PATHS_N];
} xsock_cfg_s;

static net_device_s* xdev;

#if XSOCK_SERVER
static xsock_host_s hosts[XSOCK_HOSTS_N];
#else
static xsock_host_s host[1];
#endif

static const xsock_cfg_s cfg = {
    .clt = {
        { .oPkts = XCONF_XSOCK_CLT_PATH_0_PKTS, .oBurst = HZ/4, .oTime = 10,               .itfc = XCONF_XSOCK_CLT_PATH_0_ITFC, .mac = XCONF_XSOCK_CLT_PATH_0_MAC, .gw = XCONF_XSOCK_CLT_PATH_0_GW, .addr = {XCONF_XSOCK_CLT_PATH_0_ADDR_0,XCONF_XSOCK_CLT_PATH_0_ADDR_1,XCONF_XSOCK_CLT_PATH_0_ADDR_2,XCONF_XSOCK_CLT_PATH_0_ADDR_3}, },
#if XSOCK_PATHS_N > 1
        { .oPkts = XCONF_XSOCK_CLT_PATH_1_PKTS, .oBurst = HZ/4, .oTime = 10,               .itfc = XCONF_XSOCK_CLT_PATH_1_ITFC, .mac = XCONF_XSOCK_CLT_PATH_1_MAC, .gw = XCONF_XSOCK_CLT_PATH_1_GW, .addr = {XCONF_XSOCK_CLT_PATH_1_ADDR_0,XCONF_XSOCK_CLT_PATH_1_ADDR_1,XCONF_XSOCK_CLT_PATH_1_ADDR_2,XCONF_XSOCK_CLT_PATH_1_ADDR_3}, },
#if XSOCK_PATHS_N > 2
        { .oPkts = XCONF_XSOCK_CLT_PATH_2_PKTS, .oBurst = HZ/4, .oTime = 10,               .itfc = XCONF_XSOCK_CLT_PATH_2_ITFC, .mac = XCONF_XSOCK_CLT_PATH_2_MAC, .gw = XCONF_XSOCK_CLT_PATH_2_GW, .addr = {XCONF_XSOCK_CLT_PATH_2_ADDR_0,XCONF_XSOCK_CLT_PATH_2_ADDR_1,XCONF_XSOCK_CLT_PATH_2_ADDR_2,XCONF_XSOCK_CLT_PATH_2_ADDR_3}, },
#if XSOCK_PATHS_N > 3
        { .oPkts = XCONF_XSOCK_CLT_PATH_3_PKTS, .oBurst = HZ/4, .oTime = 10,               .itfc = XCONF_XSOCK_CLT_PATH_3_ITFC, .mac = XCONF_XSOCK_CLT_PATH_3_MAC, .gw = XCONF_XSOCK_CLT_PATH_3_GW, .addr = {XCONF_XSOCK_CLT_PATH_3_ADDR_0,XCONF_XSOCK_CLT_PATH_3_ADDR_1,XCONF_XSOCK_CLT_PATH_3_ADDR_2,XCONF_XSOCK_CLT_PATH_3_ADDR_3}, },
#endif
#endif
#endif
    },
    .srv = {
        { .oPkts = XCONF_XSOCK_SRV_PATH_0_PKTS, .oBurst = HZ/4, .oTime = 10, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_0_ITFC, .mac = XCONF_XSOCK_SRV_PATH_0_MAC, .gw = XCONF_XSOCK_SRV_PATH_0_GW, .addr = {XCONF_XSOCK_SRV_PATH_0_ADDR_0,XCONF_XSOCK_SRV_PATH_0_ADDR_1,XCONF_XSOCK_SRV_PATH_0_ADDR_2,XCONF_XSOCK_SRV_PATH_0_ADDR_3}, },
#if XSOCK_PATHS_N > 1
        { .oPkts = XCONF_XSOCK_SRV_PATH_1_PKTS, .oBurst = HZ/4, .oTime = 10, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_1_ITFC, .mac = XCONF_XSOCK_SRV_PATH_1_MAC, .gw = XCONF_XSOCK_SRV_PATH_1_GW, .addr = {XCONF_XSOCK_SRV_PATH_1_ADDR_0,XCONF_XSOCK_SRV_PATH_1_ADDR_1,XCONF_XSOCK_SRV_PATH_1_ADDR_2,XCONF_XSOCK_SRV_PATH_1_ADDR_3}, },
#if XSOCK_PATHS_N > 2
        { .oPkts = XCONF_XSOCK_SRV_PATH_2_PKTS, .oBurst = HZ/4, .oTime = 10, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_2_ITFC, .mac = XCONF_XSOCK_SRV_PATH_2_MAC, .gw = XCONF_XSOCK_SRV_PATH_2_GW, .addr = {XCONF_XSOCK_SRV_PATH_2_ADDR_0,XCONF_XSOCK_SRV_PATH_2_ADDR_1,XCONF_XSOCK_SRV_PATH_2_ADDR_2,XCONF_XSOCK_SRV_PATH_2_ADDR_3}, },
#if XSOCK_PATHS_N > 3
        { .oPkts = XCONF_XSOCK_SRV_PATH_3_PKTS, .oBurst = HZ/4, .oTime = 10, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_3_ITFC, .mac = XCONF_XSOCK_SRV_PATH_3_MAC, .gw = XCONF_XSOCK_SRV_PATH_3_GW, .addr = {XCONF_XSOCK_SRV_PATH_3_ADDR_0,XCONF_XSOCK_SRV_PATH_3_ADDR_1,XCONF_XSOCK_SRV_PATH_3_ADDR_2,XCONF_XSOCK_SRV_PATH_3_ADDR_3}, },
#endif
#endif
#endif
    }
};

static wire_hash_t xsock_out_encrypt (void* data, uint size) {

    (void)data;
    (void)size;

    return size;
}

static wire_hash_t xsock_in_decrypt (void* data, uint size) {

    (void)data;
    (void)size;

    return size;
}

// TODO: FIXME: PROTECT THE REAL SERVER TCP PORTS SO WE DON'T NEED TO BIND TO THE FAKE INTERFACE
static rx_handler_result_t xsock_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    // TODO: FIXME: DESCOBRIR O QUE CAUSA TANTOS SKBS NAO LINEARES AQUI
    // TODO: FIXME: pskb vs skb??? sera que vai te rque fazer skb_copy() e depois *pskb = skb ?
    // e aí faz ou não kfree_skb()?
    if (skb_linearize(skb))
        goto drop;

    xsock_wire_s* const wire = SKB_DATA(skb) - offsetof(xsock_wire_s, iVersionTOS);

    // CONFIRM PACKET SIZE
    // CONFIRM THIS IS ETHERNET/IPV4/UDP
    if (PTR(wire) + sizeof(*wire) > SKB_TAIL(skb)
|| WIRE_ETH(wire)                 < SKB_HEAD(skb)
         || wire->eType != BE16(ETH_P_IP)
         || wire->iProtocol != IPPROTO_UDP)
        return RX_HANDLER_PASS;

#if XSOCK_SERVER
    const uint srvPort = BE16(wire->ports[1]);
#else
    const uint srvPort = BE16(wire->ports[0]);
    const uint cltPort = BE16(wire->ports[1]);
#endif

    // SE NAO FOR NA MINHA PORTA, ENTAO NAO INTERPRETA COMO XSOCK
#if XSOCK_SERVER
    if (srvPort < PORT(0, 0)
     || srvPort > PORT(XSOCK_HOSTS_N - 1,
                       XSOCK_PATHS_N - 1))
#else
    if (cltPort != BE16(XSOCK_PORT))
#endif
        return RX_HANDLER_PASS;

    // IDENTIFY HOST, PATH AND CONN
    const uint hid = PORT_HID(srvPort);
    const uint pid = PORT_PID(srvPort);
    const uint cid = BE16(wire->iCID);

    // VALIDATE HOST ID
#if XSOCK_SERVER
    if (hid >= XSOCK_HOSTS_N)
#else
    if (hid != XSOCK_HOST_ID)
#endif
        goto drop;

    // VALIDATE PATH ID
    if (pid >= XSOCK_PATHS_N)
        goto drop;

    // GET THE SIZE OF THE ORIGINAL PACKET
    const uint ipSize = BE16(wire->iSize) - sizeof(wire_hash_t);

    // DROP INCOMPLETE PACKETS
    if ((WIRE_IP(wire) + ipSize + sizeof(wire_hash_t)) > SKB_TAIL(skb))
        goto drop;

    // DECRYPT AND CONFIRM AUTHENTICITY
    if (xsock_in_decrypt(WIRE_UDP_PAYLOAD(wire), ipSize - 28)
        != BE32(*wire_hash(wire, ipSize)))
        goto drop;

    // DETECT AND UPDATE PATH CHANGES AND AVAILABILITY
#if XSOCK_SERVER
    const u64 hash = (u64)(uintptr_t)skb->dev
      + *(u64*)wire->eDst // VAI PEGAR UM PEDAÇO DO eSrc
      + *(u64*)wire->eSrc // VAI PEGAR O eType
      + *(u64*)wire->iAddrs // VAI PEGAR O iDst
      + *(u32*)wire->ports // VAI PEGAR AMBAS AS PORTAS MAS O SERVER PORT É FIXO PARA ESTE HOST:PATH
    ;

    xsock_host_s* const host = &hosts[hid];
    xsock_path_s* const path = &host->paths[pid];

                 path->iActive = jiffies + path->iTimeout*HZ;
    if (unlikely(path->iHash != hash)) {
                 path->iHash =  hash;
                 path->itfc = skb->dev; // NOTE: SE CHEGOU ATÉ AQUI ENTÃO É UMA INTERFACE JÁ HOOKADA
                 path->eDst[0]   = wire->eSrc[0];
                 path->eDst[1]   = wire->eSrc[1];
                 path->eDst[2]   = wire->eSrc[2];
                 path->eSrc[0]   = wire->eDst[0];
                 path->eSrc[1]   = wire->eDst[1];
                 path->eSrc[2]   = wire->eDst[2];
                 path->iAddrs[1] = wire->iAddrs[0];
                 path->iAddrs[0] = wire->iAddrs[1];
                 path->cport     = wire->ports[0];

        printk_host("PATH %u: UPDATED WITH HASH 0x%016llX ITFC %s"
            " %04X%04X%04X 0x%08X %u ->"
            " %04X%04X%04X 0x%08X %u\n",
            pid, (uintll)path->iHash, path->itfc->name,
            _MAC(path->eSrc), _IP4(path->iAddrs[0]), BE16(wire->ports[1]),
            _MAC(path->eDst), _IP4(path->iAddrs[1]), BE16(path->cport));
    }
#endif

    // RE-ENCAPSULATE
#if XSOCK_SERVER
    wire->iAddrs[0] = BE32(ADDR_CLT + hid);
    wire-> ports[0] = BE16(cid);
    wire->iAddrs[1] = BE32(ADDR_SRV);
    wire-> ports[1] = BE16(XSOCK_PORT);
#else
    wire->iAddrs[0] = BE32(ADDR_SRV);
    wire-> ports[0] = BE16(XSOCK_PORT);
    wire->iAddrs[1] = BE32(ADDR_CLT + hid);
    wire-> ports[1] = BE16(cid);
#endif
    wire->iTTL      = 64;
    wire->iProtocol = IPPROTO_TCP;
    wire->iSize     = BE16(ipSize);
    wire->iChecksum = 0;
    wire->iChecksum = ip_fast_csum(WIRE_IP(wire), 5);
    wire->tSeq      = wire->tSeq2;
    wire->tSeq2     = 0;

    // TODO: FIXME: SKB TRIM QUE NEM É FEITO NO ip_rcv_core()
    skb->data            = WIRE_IP(wire);
    skb->mac_header      = WIRE_IP(wire) - PTR(skb->head);
    skb->network_header  = WIRE_IP(wire) - PTR(skb->head);
    skb->len             = ipSize;
    skb->mac_len         = 0;
    skb->ip_summed       = CHECKSUM_UNNECESSARY;
    skb->csum_valid      = 1;
    skb->dev             = xdev;

    *pskb = skb;

    return RX_HANDLER_ANOTHER;

drop:
    kfree_skb(skb);

    *pskb = NULL;

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xsock_out (sk_buff_s* const skb, net_device_s* const dev) {

    if (skb_linearize(skb))
        goto drop;

    xsock_wire_s* const wire = PTR(skb->data)
        + sizeof(struct iphdr)
        + sizeof(struct tcphdr)
       - sizeof(*wire);

    if (WIRE_ETH(wire) < PTR(skb->head)
#if XSOCK_SERVER
          || wire->iAddrs[0] != BE32(ADDR_SRV)
          || wire-> ports[0] != BE16(XSOCK_PORT)
#else
          || wire->iAddrs[0] != BE32(ADDR_CLT + XSOCK_HOST_ID)
          || wire->iAddrs[1] != BE32(ADDR_SRV)
          || wire-> ports[1] != BE16(XSOCK_PORT)
#endif
    )
        goto drop;

#if XSOCK_SERVER
    const uint hid = (BE32(wire->iAddrs[1]) & 0xFFU) - 1;

    if (hid >= XSOCK_HOSTS_N)
        goto drop;

    xsock_host_s* const host = &hosts[hid];
#endif

#if XSOCK_SERVER
    const uint cid = BE16(wire->ports[1]);
#else
    const uint cid = BE16(wire->ports[0]);
#endif

    xsock_conn_s* const conn = &host->conns[cid];

    // TODO: FIXME: NO CLIENTE, SALVAR O ACK&SEQ DO SYN COMO BASE DO KEY
    if (wire->tFlags & XSOCK_WIRE_TCP_SYN)
        conn->cdown = 3*XSOCK_PATHS_N;

    if (conn->cdown) {
        conn->cdown--;
        conn->pkts = 0;
    }

uint pid = conn->pid;
    const xsock_path_s* path = &host->paths[pid];

    const u64 now = jiffies;

    // CHOOSE PATH
    if (conn->pkts == 0
     || conn->burst < now
     || conn->limit < now
#if XSOCK_SERVER
     || path->iActive < now
#endif
     || path->itfc == NULL
   || !(path->itfc->flags & IFF_UP)) {

        // TRY THIS ONE AGAIN AS IT MAY BE OKAY, JUST BURSTED OUT
        uint c = XSOCK_PATHS_N;

        do { // PATH INUSABLE
            if (!c--)
                // NENHUM PATH DISPONÍVEL
                goto drop;
            // GO TO NEXT PATH
            path = &host->paths[(pid = (pid + 1) % XSOCK_PATHS_N)];
        } while (!(
            path->oPkts
#if XSOCK_SERVER
         && path->iActive >= now
#endif
         && path->itfc
         && path->itfc->flags & IFF_UP
        ));

        //
        if (conn->pid !=        pid) {
            conn->pid  =        pid;
            conn->pkts  =       path->oPkts;
            conn->limit = now + path->oTime*HZ;
        }
    } else
        conn->pkts--;

    conn->burst = now + path->oBurst;

    // TODO: CONFIRM WE HAVE THIS FREE SPACE
    const uint ipSize = BE16(wire->iSize) + sizeof(wire_hash_t);

    // RE-ENCAPSULATE
    // SALVA ANTES DE SOBRESCREVER
           wire->tSeq2        = wire->tSeq;
           wire->uSize        = BE16(ipSize - 20);
           wire->uChecksum    = 0;
#if XSOCK_SERVER
           wire->ports[0]         = BE16(PORT(hid, pid));
           wire->ports[1]         = path->cport; // THE CLIENT IS BEHIND NAT
#else
           wire->ports[0]         = BE16(XSOCK_PORT);
           wire->ports[1]         = BE16(PORT(XSOCK_HOST_ID, pid));
#endif
    *(u64*)wire->iAddrs       = *(u64*)path->iAddrs;
           wire->iCID         = BE16(cid);
           wire->iSize        = BE16(ipSize);
           wire->iTTL         = 64;
           wire->iProtocol    = IPPROTO_UDP;
           wire->iChecksum    = 0;
           wire->iChecksum    = ip_fast_csum(WIRE_IP(wire), 5);
   ((u64*)WIRE_ETH(wire))[0] = ((u64*)(&path->eDst))[0];
   ((u64*)WIRE_ETH(wire))[1] = ((u64*)(&path->eDst))[1];

    //
    *wire_hash(wire, ipSize - sizeof(wire_hash_t))
        = BE32(xsock_out_encrypt(WIRE_UDP_PAYLOAD(wire), ipSize - 32));

    skb->data             = WIRE_ETH(wire);
    skb->mac_header       = WIRE_ETH(wire) - PTR(skb->head);
    skb->network_header   = WIRE_IP (wire)  - PTR(skb->head);
    skb->transport_header = WIRE_UDP(wire) - PTR(skb->head);
    skb->mac_len          = ETH_HLEN;
    skb->len              = ETH_HLEN + ipSize;
    skb->ip_summed        = CHECKSUM_NONE;
    skb->dev              = path->itfc;

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
    dev_queue_xmit(skb);

    return NETDEV_TX_OK;

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xsock_up (net_device_s* const dev) {

    printk("XSOCK: UP\n");

    return 0;
}

static int xsock_down (net_device_s* const dev) {

    printk("XSOCK: DOWN\n");

    return 0;
}

static const net_device_ops_s xsockDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  xsock_up,
    .ndo_stop             =  xsock_down,
    .ndo_start_xmit       =  xsock_out,
    .ndo_set_mac_address  =  NULL,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void xsock_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xsockDevOps;
    dev->header_ops      = NULL;
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
                         | IFF_NO_RX_HANDLER
                         | IFF_LIVE_ADDR_CHANGE
                         | IFF_LIVE_RENAME_OK
        ;
    dev->features        =
    dev->hw_features     = NETIF_F_RXCSUM
                         | NETIF_F_HW_CSUM
        ;
}

static int __init xsock_init (void) {

#if XSOCK_SERVER
    printk("XSOCK: SERVER INIT\n");
#else
    printk("XSOCK: CLIENT INIT\n");
#endif
    BUILD_BUG_ON(sizeof(xsock_wire_s) != XSOCK_WIRE_SIZE);
    BUILD_BUG_ON(sizeof(xsock_path_s) != XSOCK_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xsock_conn_s) != XSOCK_CONN_SIZE);

    // CREATE THE VIRTUAL INTERFACE
    net_device_s* const dev = alloc_netdev(0, "xsock", NET_NAME_USER, xsock_setup);

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

#if XSOCK_SERVER
    memset(hosts, 0, sizeof(hosts));
#else
    memset(host, 0, sizeof(host));
#endif

    // INITIALIZE HOSTS
#if XSOCK_SERVER
    foreach (hid, XSOCK_HOSTS_N) {

        xsock_host_s* const host = &hosts[hid];
#endif
        printk_host("INITIALIZING\n");

        // INITIALIZE CONNECTIONS
        // conn[*].pid
        // conn[*].burst
        // conn[*].limit     ---> 0
        // conn[*].pkts
        // conn[*].cdown

        // INITIALIZE PATHS
        foreach (pid, XSOCK_PATHS_N) {

            xsock_path_s* const path = &host->paths[pid];

#if XSOCK_SERVER
            const xsock_cfg_path_s* const this = &cfg.srv[pid];
            const xsock_cfg_path_s* const peer = &cfg.clt[pid];
#else
            const xsock_cfg_path_s* const this = &cfg.clt[pid];
            const xsock_cfg_path_s* const peer = &cfg.srv[pid];
#endif
            printk_host("PATH %u: INITIALIZING WITH OUT BURST %uj MAX %up %us IN TIMEOUT %us ITFC %s"
                " %04X%04X%04X 0x%08X ->"
                " %04X%04X%04X 0x%08X\n",
                pid,
                this->oBurst,
                this->oPkts,
                this->oTime,
                this->iTimeout,
                this->itfc,
                _MAC(this->mac), _IP4(this->addr32),
                _MAC(this->gw),  _IP4(peer->addr32)
            );

         // path->itfc      --> 0
            path->oPkts     = this->oPkts;
            path->oBurst    = this->oBurst;
            path->oTime     = this->oTime;
#if XSOCK_SERVER
         // path->iHash     --> 0
         // path->iActive   --> 0
            path->iTimeout  = this->iTimeout;
         // path->reserved0 --> 0
         // path->cport     --> 0
#else
         // path->reserved0 --> 0
         // path->reserved1 --> 0
         // path->reserved2 --> 0
         // path->reserved3 --> 0
#endif
            path->eDst[0]     = this->eSrc[0];
            path->eDst[1]     = this->eSrc[1];
            path->eDst[2]     = this->eSrc[2];
            path->eSrc[0]     = this->eDst[0];
            path->eSrc[1]     = this->eDst[1];
            path->eSrc[2]     = this->eDst[2];
            path->eType       = BE16(ETH_P_IP);
            path->iVersionTOS = BE16(0x4500U);
            path->iAddrs[0]   = this->addr32;
            path->iAddrs[1]   = peer->addr32;

            net_device_s* const itfc = dev_get_by_name(&init_net, this->itfc);

            if (itfc) { // TODO: FIXME: VAI TER QUE USAR O rx_handler_data COMO USAGE COUNT

                printk_host("PATH %u: INTERFACE HOOKING %s\n", pid, itfc->name);

                rtnl_lock();

                // HOOK INTERFACE
                if (rcu_dereference(itfc->rx_handler) != xsock_in) {
                    // NOT HOOKED YET
                    if (!netdev_rx_handler_register(itfc, xsock_in, NULL)) {
                        // HOOK SUCCESS
                        //itfc->usage = 1;
                        path->itfc = itfc;
                    }
                } else { // ALREADY HOOKED
                    //itfc->usage++;
                    path->itfc = itfc;
                }

                rtnl_unlock();

                if (path->itfc)
                    printk_host("PATH %u: INTERFACE HOOKED\n", pid);
                else { // TODO: LEMBRAR O NOME ENTÃO - APONTAR PARA O CONFIG?
                    printk_host("PATH %u: INTERFACE NOT HOOKED\n", pid);
                    dev_put(itfc);
                }
            } else
                printk_host("PATH %u: INTERFACE NOT FOUND\n", pid);
        }
#if XSOCK_SERVER
    }
#endif

    return 0;
}

static void __exit xsock_exit (void) {

    printk("XSOCK: EXIT\n");

    //
    if (xdev) {
        unregister_netdev(xdev);
        free_netdev(xdev);
    }

    //
#if XSOCK_SERVER
    foreach (hid, XSOCK_HOSTS_N) {

        xsock_host_s* const host = &hosts[hid];
#endif
        foreach (pid, XSOCK_PATHS_N) {

            net_device_s* itfc = host->paths[pid].itfc;

            if (itfc) {

                printk_host("PATH %u: INTERFACE UNHOOKING %s\n", pid, itfc->name);

                rtnl_lock();

                if (rcu_dereference(itfc->rx_handler) == xsock_in)
                    netdev_rx_handler_unregister(itfc);

                rtnl_unlock();

                // O PATH NAO SE REFERE MAIS A ESSA INTERFACE
                dev_put(itfc);
            }
        }
#if XSOCK_SERVER
    }
#endif
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

// TODO: NAO CALCULAR O CHECKSUM IP E TCP ANTES DE PASSAR PARA A INTERFACE XGW
