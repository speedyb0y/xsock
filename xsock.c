/*

    TODO: RETIRAR TAIS PORTAS DOS EPHEMERAL PORTS
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

#define SKB_HEAD(skb) PTR((skb)->head)
#define SKB_DATA(skb) PTR((skb)->data)
#define SKB_TAIL(skb) PTR(skb_tail_pointer(skb))
#define SKB_END(skb)  PTR(skb_end_pointer(skb))

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
#define XSOCK_HOSTS_N     XCONF_XSOCK_HOSTS_N
#define XSOCK_PATHS_N     XCONF_XSOCK_PATHS_N
#define XSOCK_HOST_ID     XCONF_XSOCK_HOST_ID

#define VADDR_CLT 0xC0000000U // 192.0.0.0
#define VADDR_SRV 0xC00000FFU // 192.0.0.255

#define VPORT_CLT 4000
#define VPORT_SRV 2000

#if ! (1 <= XSOCK_PORT && XSOCK_PORT <= 0xFFFF)
#error "BAD XSOCK_PORT"
#endif

#if ! (1 <= XSOCK_HOSTS_N && XSOCK_HOSTS_N <= 254)
#error "BAD XSOCK_HOSTS_N"
#endif

#if ! (1 <= XSOCK_PATHS_N && XSOCK_PATHS_N <= 4)
#error "BAD XSOCK_PATHS_N"
#endif

#if XSOCK_SERVER
#if ! (0 <= XSOCK_HOST_ID && XSOCK_HOST_ID < 0xFF)
#error "BAD XSOCK_HOST_ID"
#endif
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

#if XSOCK_SERVER
#define printk_host(msg, ...) printk("XSOCK: HOST: %u " msg, hid, ##__VA_ARGS__)
#else
#define printk_host(msg, ...) printk("XSOCK: " msg, ##__VA_ARGS__)
#endif

#ifdef __BIG_ENDIAN
#define XSOCK_TCP_FLAGS_CWR 0b0000000010000000U
#define XSOCK_TCP_FLAGS_ECE 0b0000000001000000U
#define XSOCK_TCP_FLAGS_URG 0b0000000000100000U
#define XSOCK_TCP_FLAGS_ACK 0b0000000000010000U
#define XSOCK_TCP_FLAGS_PSH 0b0000000000001000U
#define XSOCK_TCP_FLAGS_RST 0b0000000000000100U
#define XSOCK_TCP_FLAGS_SYN 0b0000000000000010U
#define XSOCK_TCP_FLAGS_FIN 0b0000000000000001U
#else
#define XSOCK_TCP_FLAGS_CWR 0b1000000000000000U
#define XSOCK_TCP_FLAGS_ECE 0b0100000000000000U
#define XSOCK_TCP_FLAGS_URG 0b0010000000000000U
#define XSOCK_TCP_FLAGS_ACK 0b0001000000000000U
#define XSOCK_TCP_FLAGS_PSH 0b0000100000000000U
#define XSOCK_TCP_FLAGS_RST 0b0000010000000000U
#define XSOCK_TCP_FLAGS_SYN 0b0000001000000000U
#define XSOCK_TCP_FLAGS_FIN 0b0000000100000000U
#endif

#define WIRE_ETH(wire)     PTR(&(wire)->eDst)
#define WIRE_IP(wire)      PTR(&(wire)->iVersion)
#define WIRE_UDP(wire)     PTR(&(wire)->uSrc)
#define WIRE_PAYLOAD(wire) PTR(&(wire)->tAck)

// ENCAPSULED IP SIZE -> PAYLOAD SIZE
#define WIRE_PAYLOAD_SIZE(ipSize) ((ipSize) - ( \
    offsetof(xsock_wire_s, tAck) - \
    offsetof(xsock_wire_s, iVersion) \
    ))

//
typedef u32 xsock_wire_hash_t;

// EXPECTED SIZE
#define XSOCK_WIRE_SIZE 64

typedef struct xsock_wire_s {
// 6 ALIGNMENT
    u16 _align[3];
// 14 ETH
    u16 eDst[ETH_ALEN/sizeof(u16)];
    u16 eSrc[ETH_ALEN/sizeof(u16)];
    u16 eType;
// 20 IP
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iCID; // CONNECTION ID (CLIENT SOURCE (EPHEMERAL) PORT)
    u16 iFrag;
    u8  iTTL;
    u8  iProtocol;
    u16 iChecksum;
    u32 iSrc;
    u32 iDst;
// 8 UDP
    u16 uSrc;
    u16 uDst;
    u16 uSize;
    u16 uChecksum;
// 16 TCP REMAINING
    u32 xHash;
    u32 tAck;
    u16 tFlags;
    u16 tWindow;
    u32 tSeq; // CHECKSUM, URGENT
// TCP PAYLOAD
} xsock_wire_s;

#define XSOCK_ORIG_SIZE 64

typedef struct xsock_orig_s {
// 10 ALIGNMENT
    u16 _align[5];
// 14 ETH
    u16 eDst[ETH_ALEN/sizeof(u16)];
    u16 eSrc[ETH_ALEN/sizeof(u16)];
    u16 eType;
// 20 IP
    u8  iVersion;
    u8  iTOS;
    u16 iSize;
    u16 iID;
    u16 iFrag;
    u8  iTTL;
    u8  iProtocol;
    u16 iChecksum;
    u32 iSrc;
    u32 iDst;
// 20 TCP
    u16 tSrc;
    u16 tDst;
    u32 tSeq;
    u32 tAck;
    u16 tFlags;
    u16 tWindow;
    u32 tSeq2; // CHECKSUM, URGENT
// TCP PAYLOAD
} xsock_orig_s;

// EXPECTED SIZE
#define XSOCK_PATH_SIZE CACHE_LINE_SIZE

typedef struct xsock_path_s {
    net_device_s* itfc;
    u32 oLast; // ULTIMA VEZ QUE ENVIOU - ENTAO DE LA ATE NOW PASSARAM-SE N DIFFIES
    u32 oRemaining;
    u32 oPkts;
#if XSOCK_SERVER // TODO: FIXME: NO CLIENTE USAR ISSO TAMBÉM, MAS DE TEMPOS EM TEMPOS TENTAR RESTAURAR, E COM VALORES MENORES DE PKTS E TIME
    u16 uDst;
    u16 iTimeout; // MÁXIMO DE TEMPO (EM SEGUNDOS) QUE PODE FICAR SEM RECEBER NADA E AINDA ASSIM CONSIDERAR COMO FUNCIONANDO
    u64 iActive; //  [IN LAST]  ATÉ ESTE TIME (EM JIFFIES), CONSIDERA QUE A CONEXÃO ESTÁ ATIVA
    u64 iHash; // THE PATH HASH
#else
    u32 reserved0;
    u64 reserved1;
    u64 reserved2;
#endif
    u16 eDst[ETH_ALEN/sizeof(u16)];
    u16 eSrc[ETH_ALEN/sizeof(u16)];
    u16 eType;
    u8  iVersion;
    u8  iTOS;
    u32 iSrc;
    u32 iDst;
} xsock_path_s;

#define O_PKTS_SHIFT 11
#define O_PKTS_UNIT (1U << O_PKTS_SHIFT)

// O BURST É RELATIVO A CONEXAO E É ESPECIFICO DA ATIVIDADE DO SERVICO
#if XSOCK_SERVER
#define CONN_BURST (HZ/5)
#else
#define CONN_BURST (HZ/5)
#endif

// CONSIDERING THE WITDH
#define XSOCK_CONN_BURST_MASK ((1ULL << 60) - 1)

// EXPECTED SIZE
#define XSOCK_CONN_SIZE 8

typedef struct xsock_conn_s {
    u64 burst:60,
        cdown:2,
        pid:2;
} xsock_conn_s;

typedef struct xsock_host_s {
    spinlock_t lock;
    char _pad[CACHE_LINE_SIZE - sizeof(spinlock_t)];
    xsock_path_s paths[XSOCK_PATHS_N];
    xsock_conn_s conns[XSOCK_CONNS_N];
} xsock_host_s;

typedef struct xsock_cfg_path_s {
    char itfc[IFNAMSIZ];
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
    .clt = { // .oBurst = HZ/4
        { .oPkts = XCONF_XSOCK_CLT_PATH_0_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_0_ITFC, .mac = XCONF_XSOCK_CLT_PATH_0_MAC, .gw = XCONF_XSOCK_CLT_PATH_0_GW, .addr = {XCONF_XSOCK_CLT_PATH_0_ADDR_0,XCONF_XSOCK_CLT_PATH_0_ADDR_1,XCONF_XSOCK_CLT_PATH_0_ADDR_2,XCONF_XSOCK_CLT_PATH_0_ADDR_3}, },
#if XSOCK_PATHS_N > 1
        { .oPkts = XCONF_XSOCK_CLT_PATH_1_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_1_ITFC, .mac = XCONF_XSOCK_CLT_PATH_1_MAC, .gw = XCONF_XSOCK_CLT_PATH_1_GW, .addr = {XCONF_XSOCK_CLT_PATH_1_ADDR_0,XCONF_XSOCK_CLT_PATH_1_ADDR_1,XCONF_XSOCK_CLT_PATH_1_ADDR_2,XCONF_XSOCK_CLT_PATH_1_ADDR_3}, },
#if XSOCK_PATHS_N > 2
        { .oPkts = XCONF_XSOCK_CLT_PATH_2_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_2_ITFC, .mac = XCONF_XSOCK_CLT_PATH_2_MAC, .gw = XCONF_XSOCK_CLT_PATH_2_GW, .addr = {XCONF_XSOCK_CLT_PATH_2_ADDR_0,XCONF_XSOCK_CLT_PATH_2_ADDR_1,XCONF_XSOCK_CLT_PATH_2_ADDR_2,XCONF_XSOCK_CLT_PATH_2_ADDR_3}, },
#if XSOCK_PATHS_N > 3
        { .oPkts = XCONF_XSOCK_CLT_PATH_3_PKTS, .itfc = XCONF_XSOCK_CLT_PATH_3_ITFC, .mac = XCONF_XSOCK_CLT_PATH_3_MAC, .gw = XCONF_XSOCK_CLT_PATH_3_GW, .addr = {XCONF_XSOCK_CLT_PATH_3_ADDR_0,XCONF_XSOCK_CLT_PATH_3_ADDR_1,XCONF_XSOCK_CLT_PATH_3_ADDR_2,XCONF_XSOCK_CLT_PATH_3_ADDR_3}, },
#endif
#endif
#endif
    },
    .srv = { // .oBurst = HZ/4
        { .oPkts = XCONF_XSOCK_SRV_PATH_0_PKTS, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_0_ITFC, .mac = XCONF_XSOCK_SRV_PATH_0_MAC, .gw = XCONF_XSOCK_SRV_PATH_0_GW, .addr = {XCONF_XSOCK_SRV_PATH_0_ADDR_0,XCONF_XSOCK_SRV_PATH_0_ADDR_1,XCONF_XSOCK_SRV_PATH_0_ADDR_2,XCONF_XSOCK_SRV_PATH_0_ADDR_3}, },
#if XSOCK_PATHS_N > 1
        { .oPkts = XCONF_XSOCK_SRV_PATH_1_PKTS, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_1_ITFC, .mac = XCONF_XSOCK_SRV_PATH_1_MAC, .gw = XCONF_XSOCK_SRV_PATH_1_GW, .addr = {XCONF_XSOCK_SRV_PATH_1_ADDR_0,XCONF_XSOCK_SRV_PATH_1_ADDR_1,XCONF_XSOCK_SRV_PATH_1_ADDR_2,XCONF_XSOCK_SRV_PATH_1_ADDR_3}, },
#if XSOCK_PATHS_N > 2
        { .oPkts = XCONF_XSOCK_SRV_PATH_2_PKTS, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_2_ITFC, .mac = XCONF_XSOCK_SRV_PATH_2_MAC, .gw = XCONF_XSOCK_SRV_PATH_2_GW, .addr = {XCONF_XSOCK_SRV_PATH_2_ADDR_0,XCONF_XSOCK_SRV_PATH_2_ADDR_1,XCONF_XSOCK_SRV_PATH_2_ADDR_2,XCONF_XSOCK_SRV_PATH_2_ADDR_3}, },
#if XSOCK_PATHS_N > 3
        { .oPkts = XCONF_XSOCK_SRV_PATH_3_PKTS, .iTimeout = 35, .itfc = XCONF_XSOCK_SRV_PATH_3_ITFC, .mac = XCONF_XSOCK_SRV_PATH_3_MAC, .gw = XCONF_XSOCK_SRV_PATH_3_GW, .addr = {XCONF_XSOCK_SRV_PATH_3_ADDR_0,XCONF_XSOCK_SRV_PATH_3_ADDR_1,XCONF_XSOCK_SRV_PATH_3_ADDR_2,XCONF_XSOCK_SRV_PATH_3_ADDR_3}, },
#endif
#endif
#endif
    }
};

#define popcount32(x) __builtin_popcount((uint)(x))
#define popcount64(x) __builtin_popcountll((uintll)(x))

static inline u64 swap64 (u64 x, const u64 mask) {

    const uint q = popcount64(mask);

    x += mask;
    x = (x >> q) | (x << (64 - q));

    return x;
}

static inline u64 unswap64 (u64 x, const u64 mask) {

    const uint q = popcount64(mask);

    x = (x << q) | (x >> (64 - q));
    x -= mask;

    return x;
}

#define A 0xE04EC65E50E04E0EULL
#define B 0x8A489FE74E0FE1E4ULL

static xsock_wire_hash_t xsock_out_encrypt (u64 a, u64 b, void* restrict data, uint size) {

    a += A + swap64(b, size);
    b += B + swap64(a, size);

    while (size >= sizeof(u64)) {
        const u64 orig = BE64(*(u64*)data);
        u64 value = orig;
        value = swap64(value, size);
        value = swap64(value, a);
        value = swap64(value, b);
        *(u64*)data = BE64(value);
        a += swap64(orig, size);
        b += swap64(a, orig);
        data += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {
        const u8 orig = *(u8*)data;
        u64 value = orig;
        value += swap64(a, size);
        value += swap64(b, size);
        value &= 0xFFU;
        *(u8*)data = value;
        a += swap64(b, orig);
        b += swap64(orig, a);
        data += sizeof(u8);
        size -= sizeof(u8);
    }

    a += b;
    a += a >> 32;
    a &= 0xFFFFFFFFULL;

    return (xsock_wire_hash_t)a;
}

static xsock_wire_hash_t xsock_in_decrypt (u64 a, u64 b, void* restrict data, uint size) {

    a += A + swap64(b, size);
    b += B + swap64(a, size);

    while (size >= sizeof(u64)) {
        u64 orig = BE64(*(u64*)data);
        orig = unswap64(orig, b);
        orig = unswap64(orig, a);
        orig = unswap64(orig, size);
        *(u64*)data = BE64(orig);
        a += swap64(orig, size);
        b += swap64(a, orig);
        data += sizeof(u64);
        size -= sizeof(u64);
    }

    while (size) {
        u64 orig = *(u8*)data;
        orig -= swap64(b, size);
        orig -= swap64(a, size);
        orig &= 0xFFU;
        *(u8*)data = orig;
        a += swap64(b, orig);
        b += swap64(orig, a);
        data += sizeof(u8);
        size -= sizeof(u8);
    }

    a += b;
    a += a >> 32;
    a &= 0xFFFFFFFFULL;

    return (xsock_wire_hash_t)a;
}

// TODO: FIXME: PROTECT THE REAL SERVER TCP PORTS SO WE DON'T NEED TO BIND TO THE FAKE INTERFACE
static rx_handler_result_t xsock_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    // TODO: FIXME: DESCOBRIR O QUE CAUSA TANTOS SKBS NAO LINEARES AQUI
    // TODO: FIXME: pskb vs skb??? sera que vai te rque fazer skb_copy() e depois *pskb = skb ?
    // e aí faz ou não kfree_skb()?
    if (skb_linearize(skb)) {
        printk("IN: DROP: NON LINEAR\n");
        goto drop;
    }

    xsock_wire_s* const wire = SKB_DATA(skb) - offsetof(xsock_wire_s, iVersion);

    // CONFIRM PACKET SIZE
    // CONFIRM THIS IS IPV4
    // CONFIRM THIS IS UDP
    // CONFIRM IT HAS NO IP OPTIONS
    // CONFIRM IT'S NOT FRAGMENTED - TODO: FIXME: IGNORE THE DON'T FRAGMENT FLAG
    if (PTR(wire) + sizeof(*wire) > SKB_TAIL(skb)
|| WIRE_ETH(wire)                 < SKB_HEAD(skb)
         || wire->iVersion != 0x45
         || wire->iFrag
         || wire->iProtocol != IPPROTO_UDP
#if !XSOCK_SERVER // SE NAO FOR NA MINHA PORTA, ENTAO NAO INTERPRETA COMO XSOCK
         || wire->uDst != BE16(XSOCK_PORT)
#endif
    )
        return RX_HANDLER_PASS;

#if XSOCK_SERVER
    const uint srvPort = BE16(wire->uDst);
#else
    const uint srvPort = BE16(wire->uSrc);
#endif

    // SE NAO FOR NA MINHA PORTA, ENTAO NAO INTERPRETA COMO XSOCK
#if XSOCK_SERVER
    if (srvPort < PORT(0, 0)
     || srvPort > PORT(XSOCK_HOSTS_N - 1,
                       XSOCK_PATHS_N - 1))
        return RX_HANDLER_PASS;
#endif

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

    // GET THE SIZE OF THE ENCAPSULATED PACKET
    const uint ipSize = BE16(wire->iSize);

    if (ipSize < sizeof(xsock_orig_s)) {
        printk("IN: DROP: SMALL\n");
        goto drop;
    }

    // DROP INCOMPLETE PACKETS
    if ((WIRE_IP(wire) + ipSize) > SKB_TAIL(skb)) {
        printk("IN: DROP: INCOMPLETE\n");
        goto drop;
    }

    // DECRYPT AND CONFIRM AUTHENTICITY
    if (wire->xHash != BE32(xsock_in_decrypt(hid, cid,
        WIRE_PAYLOAD(wire),
        WIRE_PAYLOAD_SIZE(ipSize)))) {
        printk("IN: DROP: BAD HASH\n");
        goto drop;
    }

    // DETECT AND UPDATE PATH CHANGES AND AVAILABILITY
#if XSOCK_SERVER
    const u64 hash = (u64)(uintptr_t)skb->dev
      + *(u64*)wire->eDst // VAI PEGAR UM PEDAÇO DO eSrc
      + *(u64*)wire->eSrc // VAI PEGAR O eType
     + *(u64*)&wire->iSrc // VAI PEGAR O iDst
     + *(u32*)&wire->uSrc // VAI PEGAR AMBAS AS PORTAS MAS O SERVER PORT É FIXO PARA ESTE HOST:PATH
    ;

    xsock_host_s* const host = &hosts[hid];
    xsock_path_s* const path = &host->paths[pid];

    unsigned long irqStatus;

    spin_lock_irqsave(&host->lock, irqStatus);

    if (unlikely(path->iHash != hash)) {

        path->iHash   = hash;
        path->itfc    = skb->dev; // NOTE: SE CHEGOU ATÉ AQUI ENTÃO É UMA INTERFACE JÁ HOOKADA
        path->eDst[0] = wire->eSrc[0];
        path->eDst[1] = wire->eSrc[1];
        path->eDst[2] = wire->eSrc[2];
        path->eSrc[0] = wire->eDst[0];
        path->eSrc[1] = wire->eDst[1];
        path->eSrc[2] = wire->eDst[2];
        path->iDst    = wire->iSrc;
        path->iSrc    = wire->iDst;
        path->uDst    = wire->uSrc;

        printk_host("PATH %u: UPDATED WITH HASH 0x%016llX ITFC %s"
            " 0x%04X%04X%04X 0x%08X %u ->"
            " 0x%04X%04X%04X 0x%08X %u\n",
            pid, (uintll)path->iHash, path->itfc->name,
            _MAC(path->eSrc), _IP4(path->iSrc), BE16(wire->uDst),
            _MAC(path->eDst), _IP4(path->iDst), BE16(path->uDst));
    }

    path->iActive = jiffies + path->iTimeout*HZ;

    spin_unlock_irqrestore(&host->lock, irqStatus);
#endif

    // É TUDO MENOS O HASH
    const uint origSize = ipSize - sizeof(wire->xHash);

    xsock_orig_s* const orig = WIRE_IP(wire) + sizeof(wire->xHash);

    // RE-ENCAPSULATE
    orig->iVersion  = 0x45;
    orig->iTOS      = 0;
    orig->iSize     = BE16(origSize);
    orig->iID       = 0;
    orig->iFrag     = 0;
    orig->iTTL      = 64;
    orig->iProtocol = IPPROTO_TCP;
    orig->iChecksum = 0;
#if XSOCK_SERVER
    orig->iSrc      = BE32(VADDR_CLT + hid);
    orig->iDst      = BE32(VADDR_SRV);
    orig->tSrc      = BE16(cid);
    orig->tDst      = BE16(VPORT_CLT);
#else
    orig->iSrc      = BE32(VADDR_SRV);
    orig->iDst      = BE32(VADDR_CLT + XSOCK_HOST_ID);
    orig->tSrc      = BE16(VPORT_CLT);
    orig->tDst      = BE16(cid);
#endif
    orig->tSeq      = orig->tSeq2;
    orig->tSeq2     = 0;
    orig->iChecksum = ip_fast_csum(PTR(orig), 5);

    // TODO: FIXME: SKB TRIM QUE NEM É FEITO NO ip_rcv_core()
    skb->data            = PTR(orig);
    skb->mac_header      = PTR(orig) - SKB_HEAD(skb);
    skb->network_header  = PTR(orig) - SKB_HEAD(skb);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->tail            = PTR(orig) - SKB_HEAD(skb) + origSize;
#else
    skb->tail            = PTR(orig) + origSize;
#endif
    skb->len             = origSize;
    skb->mac_len         = 0;
    skb->ip_summed       = CHECKSUM_UNNECESSARY;
    skb->csum_valid      = 1;
    skb->dev             = xdev;

    return RX_HANDLER_ANOTHER;

drop:
    kfree_skb(skb);

    *pskb = NULL;

    return RX_HANDLER_CONSUMED;
}

#if !XSOCK_SERVER
#define hid XSOCK_HOST_ID
#endif

#if XSOCK_SERVER
#define TRY_OK                   (3*XSOCK_PATHS_N)
#define TRY_OK_EXCEEDS           (2*XSOCK_PATHS_N)
#define TRY_OK_EXCEEDS_INACTIVES (1*XSOCK_PATHS_N)
#else
#define TRY_OK                   (2*XSOCK_PATHS_N)
#define TRY_OK_EXCEEDS           (1*XSOCK_PATHS_N)
#endif

static netdev_tx_t xsock_out (sk_buff_s* const skb, net_device_s* const dev) {

    if (skb_linearize(skb)) {
        printk("OUT: DROP: NON LINEAR\n");
        goto drop;
    }

    const xsock_orig_s* const orig = SKB_DATA(skb);

    uint ipSize = skb->len;

    if (ipSize < sizeof(xsock_orig_s)) {
        printk("OUT: DROP: TOO SMALL\n");
        goto drop;
    }

    if (PTR(orig) + ipSize > SKB_END(skb)) {
        printk("OUT: DROP: INCOMPLETE\n");
        goto drop;
    }

    // DON'T ALLOW INTERFERENCE FROM IPV6, ICMP, WRONG ADDRESSES/PORTS
    if (orig->iVersion != 0x45
     || orig->iProtocol != IPPROTO_TCP
#if XSOCK_SERVER
     || orig->iSrc != BE32(VADDR_SRV)
     || orig->tSrc != BE16(VPORT_SRV)
#else
     || orig->iSrc != BE32(VADDR_CLT + hid)
     || orig->iDst != BE32(VADDR_SRV)
     || orig->tDst != BE16(VPORT_SRV)
#endif
    ) {
        printk("OUT: DROP: BAD PACKET\n");
        goto drop;
    }

#if XSOCK_SERVER
    const uint hid = BE32(orig->iDst) - VADDR_CLT;

    if (hid >= XSOCK_HOSTS_N) {
        printk("OUT: DROP: BAD HID\n");
        goto drop;
    }

    xsock_host_s* const host = &hosts[hid];

    const uint cid = BE16(orig->tDst);
#else
    const uint cid = BE16(orig->tSrc);
#endif

    spin_lock_irq(&host->lock);

    xsock_conn_s* const conn = &host->conns[cid];

    const uint now = ((u64)jiffies) & XSOCK_CONN_BURST_MASK;

    // FORCE USING ALL PATHS
    //      -- TO ALLOW SERVER TO DISCOVER THEM
    //      -- TO ENFORCE A SUCCESSFULL RETRANSMISSION ON HANDSHAKE/FINALIZATION
    // NOTE: ENQUANTO RETRANSMITIR O SYN/SYN-ACK/FIN/RST, VAI FICAR RESETANDO ISSO
    const uint cdown = orig->tFlags & (
            XSOCK_TCP_FLAGS_SYN |
            XSOCK_TCP_FLAGS_RST |
            XSOCK_TCP_FLAGS_FIN
        ) ? XSOCK_PATHS_N
        : conn->cdown;

    // TODO: FIXME:    SE ESTIVERMOS ENVIANDO UMA RETRANSMISSAO, DE ACORDO COM O ACK/SEQ, ENTAO MUDAR DE PATH?
    // SE ESTA INICIANDO OU SE COMPLETOU O BURST, PASSA PARA O PRÓXIMO PATH
    uint pid = (uint)conn->pid + (cdown || conn->burst < now);

    uint c = TRY_OK;

    // CHOOSE PATH
    xsock_path_s* path;

    loop { path = &host->paths[(pid %= XSOCK_PATHS_N)];

        if (path->oPkts && path->itfc && path->itfc->flags & IFF_UP) {
            // ACHOU UM PATH EXISTENTE E OK

            u64 oRemaining = path->oRemaining;

            // SE ESTE PATH JÁ ESTOUROU O LIMITE, TENTA RECONSTRUÍ-LO
            if (oRemaining < O_PKTS_UNIT) {
                oRemaining = now >= path->oLast
                        ? now - path->oLast
                        : path->oLast - now // OVERFLOWED - TODO: FIXME: FAZER A COISA CERTA
                    ;
                oRemaining *= path->oPkts;
                oRemaining += path->oRemaining;
                if (oRemaining > ((u64)path->oPkts*HZ))
                    oRemaining = ((u64)path->oPkts*HZ);
                path->oRemaining = oRemaining;
                path->oLast = now;
            }

            // NA PENULTIMA TENTATIVA, LIBERA OS EXCEEDEDS
            // NA ULTIMA TENTATIVA, LIBERA OS INATIVOS
            if ((oRemaining >= O_PKTS_UNIT || c <= TRY_OK_EXCEEDS)
#if XSOCK_SERVER
            && (path->iActive >= now || c <= TRY_OK_EXCEEDS_INACTIVES)
#endif
            ) { // ACHOU UM PATH USAVEL
                if (oRemaining >= O_PKTS_UNIT)
                    oRemaining -= O_PKTS_UNIT;
                else
                    // TODOS OS PATHS ESTÃO EXAUSTOS, RESETA O BURST DESTE
                    // MAS SÓ PELA METADE PARA COMPENSAR O FATO DE JA TER ULTRAPASSADO
                    // O QUE IMPORTA É QUE NÃO SE TRANSFORME NUMA LOUCURA DE ENVIAR 1 PACOTE EXCEDENTE EM CADA PATH
                    oRemaining = ((u64)path->oPkts*HZ)/2;
                path->oRemaining = oRemaining;
                break;
            }
        }

        // PATH INUSABLE
        if (!--c) {
            // NENHUM PATH DISPONÍVEL
            printk("OUT: DROP: NO AVAILABLE PATH\n");
            goto drop_unlock;
        }

        // GO TO NEXT PATH
        pid++;
    }

    // STORE
    conn->pid   = pid;
    conn->cdown = cdown - !!cdown;
    conn->burst = now + CONN_BURST;

    // REMEMBER AFTER UNLOCKING
    net_device_s* const itfc = path->itfc;

    // AMBOS COMPARTILHAM O MESMO FIM
    // ENTAO VAI PARA O FIM DE UM, DEPOIS VOLTA PARA O COMEÇO DO OUTRO
    xsock_wire_s* const wire = PTR(orig)
        + sizeof(xsock_orig_s)
        - sizeof(xsock_wire_s);

    //
    if (WIRE_ETH(wire) < SKB_HEAD(skb)) {
        printk("OUT: DROP: SKB START\n");
        goto drop_unlock;
    }

    // NOW THE ENCAPSULED IP SIZE
    ipSize += sizeof(wire->xHash);

    // RE-ENCAPSULATE
   ((u64*)WIRE_ETH(wire))[0] = ((u64*)(&path->eDst))[0];
   ((u64*)WIRE_ETH(wire))[1] = ((u64*)(&path->eDst))[1];

 // wire->iVersion
 // wire->iTOS
    wire->iCID        = BE16(cid);
    wire->iSize       = BE16(ipSize);
    wire->iFrag       = 0;
    wire->iTTL        = 64;
    wire->iProtocol   = IPPROTO_UDP;
    wire->iChecksum   = 0;
    wire->iSrc        = path->iSrc;
    wire->iDst        = path->iDst;
#if XSOCK_SERVER
    wire->uSrc        = BE16(PORT(hid, pid));
    wire->uDst        = path->uDst; // THE CLIENT IS BEHIND NAT
#else
    wire->uSrc        = BE16(XSOCK_PORT);
    wire->uDst        = BE16(PORT(hid, pid));
#endif
    wire->uSize       = BE16(ipSize - 20);
    wire->uChecksum   = 0;
    wire->iChecksum   = ip_fast_csum(WIRE_IP(wire), 5);
    wire->tSeq        = wire->xHash;

    spin_unlock_irq(&host->lock);

    // ENCODE
    wire->xHash = BE32(xsock_out_encrypt(hid, cid,
        WIRE_PAYLOAD(wire),
        WIRE_PAYLOAD_SIZE(ipSize)
        ));

    //
    ipSize += ETH_HLEN;

    skb->transport_header = WIRE_UDP(wire) - SKB_HEAD(skb);
    skb->network_header   = WIRE_IP (wire) - SKB_HEAD(skb);
    skb->mac_header       = WIRE_ETH(wire) - SKB_HEAD(skb);
    skb->data             = WIRE_ETH(wire);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->tail             = WIRE_ETH(wire) - SKB_HEAD(skb) + ipSize;
#else
    skb->tail             = WIRE_ETH(wire) + ipSize;
#endif
    skb->mac_len          = ETH_HLEN;
    skb->len              = ipSize;
    skb->ip_summed        = CHECKSUM_NONE;
    skb->dev              = itfc;

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
    dev_queue_xmit(skb);

    return NETDEV_TX_OK;

drop_unlock:
    spin_unlock_irq(&host->lock);

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
    dev->hard_header_len = offsetof(xsock_wire_s, iVersion) + sizeof(xsock_wire_hash_t);
    dev->min_header_len  = offsetof(xsock_wire_s, iVersion) + sizeof(xsock_wire_hash_t);
    //dev->needed_headroom = ;
    //dev->needed_tailroom = ;
    dev->min_mtu         = ETH_MAX_MTU;
    dev->max_mtu         = ETH_MAX_MTU;
    dev->mtu             = ETH_MAX_MTU;
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

    BUILD_BUG_ON(sizeof(xsock_orig_s) != XSOCK_ORIG_SIZE);
    BUILD_BUG_ON(sizeof(xsock_wire_s) != XSOCK_WIRE_SIZE);
    BUILD_BUG_ON(sizeof(xsock_wire_hash_t) != sizeof(((xsock_wire_s*)0ULL)->xHash));
    BUILD_BUG_ON(sizeof(xsock_path_s) != XSOCK_PATH_SIZE);
    BUILD_BUG_ON(sizeof(xsock_conn_s) != XSOCK_CONN_SIZE);

#if XSOCK_SERVER
    printk("XSOCK: SERVER INIT\n");
#else
    printk("XSOCK: CLIENT INIT\n");
#endif

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

        //
        spin_lock_init(&host->lock);

        // INITIALIZE CONNECTIONS
        foreach (cid, XSOCK_CONNS_N) {
            xsock_conn_s* const conn = &host->conns[cid];
            conn->pid   = cid % XSOCK_PATHS_N;
            conn->cdown = 0;
            conn->burst = 0;
        }

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
            // PEGA A LARGURA DE BANDA POSSÍVEL EM UM SEGUNDO
            // TRANSFORMA NO NÚMERO DE PACOTES
            // MAS FAZ ISSO COM 8 BITS A MAIS DE PRECISAO:
            //      ISSO/(2^8) = NUMERO REAL
            // ESTE VALOR É A QUANTIDADE DE PACOTES POR SEGUNDO.
            // DIVIDE ELE PELA QUANTIDADE DE JIFFIES EM UM SEGUNDO.
            // ESTE VALOR É A QUANTIDADE DE PACOTES QUE PODE PASSAR DURANTE UM JIFFIE.
            const uint oPkts = (((u64)this->oPkts) << O_PKTS_SHIFT) / (1500*HZ);

            printk_host("PATH %u: INITIALIZING WITH OUT BURST %uj BANDWIDTH %u BYTES/S %u PACKETS/J  IN TIMEOUT %us ITFC %s"
                " 0x%04X%04X%04X 0x%08X ->"
                " 0x%04X%04X%04X 0x%08X\n",
                pid,
                CONN_BURST,
                this->oPkts, oPkts/O_PKTS_UNIT,
                this->iTimeout,
                this->itfc,
                _MAC(this->eSrc), _IP4(this->addr32),
                _MAC(this->eDst), _IP4(peer->addr32)
            );

         // path->itfc       --> NULL
         // path->oLast      --> 0
         // path->oRemaining --> 0
            path->oPkts     = oPkts;
#if XSOCK_SERVER
         // path->uDst     --> 0
            path->iTimeout  = this->iTimeout;
         // path->iActive   --> 0
         // path->iHash     --> 0
#else
         // path->reserved0 --> 0
         // path->reserved1 --> 0
         // path->reserved2 --> 0
#endif
            path->eDst[0]    = this->eDst[0];
            path->eDst[1]    = this->eDst[1];
            path->eDst[2]    = this->eDst[2];
            path->eSrc[0]    = this->eSrc[0];
            path->eSrc[1]    = this->eSrc[1];
            path->eSrc[2]    = this->eSrc[2];
            path->eType      = BE16(ETH_P_IP);
            path->iVersion   = 0x45;
            path->iTOS       = 0;
            path->iSrc       = this->addr32;
            path->iDst       = peer->addr32;

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
TODO: CORRIGIR O XGW
no in
if (skb->len <= XSOCK_PATH_SIZE_WIRE

NO IN
e no transmit
o header nao pode ser CONST!!!
*/
