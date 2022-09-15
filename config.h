
#define VPS_A 66
#define VPS_B 206
#define VPS_C 39
#define VPS_D 49

//#define XCONF_XSOCK_HOST_ID 0
//#define IP_0_D 50
//#define ITFC0 "eth0"
//#define ITFC1 "eth1"
//#define ITFC2 "eth2"
//#define MAC0 "\xe8\xde\x27\xa6\xd2\x3a"
//#define MAC1 "\xbc\x5f\xf4\xf9\xe6\x66"
//#define MAC2 "\xbc\x5f\xf4\xf9\xe6\x67"
//#define  GW0 "\x54\x9f\x06\xf4\xc7\xa0"
//#define  GW1 "\xcc\xed\x21\x96\x99\xc0"
//#define  GW2 "\x90\x55\xde\xa1\xcd\xf0"

//#define XCONF_XSOCK_HOST_ID 1
//#define IP_0_C 0
//#define IP_0_D 20
//#define IP_1_C 100
//#define IP_1_D 20
//#define IP_2_C 1
//#define IP_2_D 20
//#define ITFC0 "eth0"
//#define ITFC1 "eth0"
//#define ITFC2 "eth0"
//#define MAC0 "\xd0\x50\x99\xae\xde\x92"
//#define MAC1 "\xd0\x50\x99\xae\xde\x92"
//#define MAC2 "\xd0\x50\x99\xae\xde\x92"
//#define  GW0 "\x54\x9f\x06\xf4\xc7\xa0"
//#define  GW1 "\xcc\xed\x21\x96\x99\xc0"
//#define  GW2 "\x90\x55\xde\xa1\xcd\xf0"

#define XCONF_XSOCK_HOST_ID 3
#define ITFC0 "eth0"
#define ITFC1 "eth0"
#define ITFC2 "eth0"
#define IP_0_C 1
#define IP_0_D 177
#define IP_1_C 1
#define IP_1_D 177
#define IP_2_C 1
#define IP_2_D 177
#define MAC0 "\x70\x5a\x0f\x68\x14\x30"
#define MAC1 "\x70\x5a\x0f\x68\x14\x30"
#define MAC2 "\x70\x5a\x0f\x68\x14\x30"
#define  GW0 "\x90\x75\xbc\x34\x19\x70"
#define  GW1 "\x90\x75\xbc\x34\x19\x70"
#define  GW2 "\x90\x75\xbc\x34\x19\x70"

// -------

#define XCONF_XSOCK_SERVER_IS 1
#define XCONF_XSOCK_PORT 2000
#define XCONF_XSOCK_HOSTS_N 4
#define XCONF_XSOCK_PATHS_N 3

#define XCONF_XSOCK_CLT_PATH_0_PKTS (10*1000000)
#define XCONF_XSOCK_CLT_PATH_1_PKTS ( 2*1000000)
#define XCONF_XSOCK_CLT_PATH_2_PKTS (15*1000000)

#define XCONF_XSOCK_SRV_PATH_0_PKTS (45*1000000)
#define XCONF_XSOCK_SRV_PATH_1_PKTS ( 8*1000000)
#define XCONF_XSOCK_SRV_PATH_2_PKTS (55*1000000)

#define XCONF_XSOCK_CLT_PATH_0_ITFC ITFC0
#define XCONF_XSOCK_CLT_PATH_0_ADDR_0 192
#define XCONF_XSOCK_CLT_PATH_0_ADDR_1 168
#define XCONF_XSOCK_CLT_PATH_0_ADDR_2 IP_0_C
#define XCONF_XSOCK_CLT_PATH_0_ADDR_3 IP_0_D
#define XCONF_XSOCK_CLT_PATH_0_MAC MAC0
#define XCONF_XSOCK_CLT_PATH_0_GW  GW0

#define XCONF_XSOCK_CLT_PATH_1_ITFC ITFC1
#define XCONF_XSOCK_CLT_PATH_1_ADDR_0 192
#define XCONF_XSOCK_CLT_PATH_1_ADDR_1 168
#define XCONF_XSOCK_CLT_PATH_1_ADDR_2 IP_1_C
#define XCONF_XSOCK_CLT_PATH_1_ADDR_3 IP_1_D
#define XCONF_XSOCK_CLT_PATH_1_MAC MAC1
#define XCONF_XSOCK_CLT_PATH_1_GW  GW1

#define XCONF_XSOCK_CLT_PATH_2_ITFC ITFC2
#define XCONF_XSOCK_CLT_PATH_2_ADDR_0 192
#define XCONF_XSOCK_CLT_PATH_2_ADDR_1 168
#define XCONF_XSOCK_CLT_PATH_2_ADDR_2 IP_2_C
#define XCONF_XSOCK_CLT_PATH_2_ADDR_3 IP_2_D
#define XCONF_XSOCK_CLT_PATH_2_MAC MAC2
#define XCONF_XSOCK_CLT_PATH_2_GW  GW2

#define XCONF_XSOCK_SRV_PATH_0_ITFC "enp1s0"
#define XCONF_XSOCK_SRV_PATH_0_ADDR_0 VPS_A
#define XCONF_XSOCK_SRV_PATH_0_ADDR_1 VPS_B
#define XCONF_XSOCK_SRV_PATH_0_ADDR_2 VPS_C
#define XCONF_XSOCK_SRV_PATH_0_ADDR_3 VPS_D
#define XCONF_XSOCK_SRV_PATH_0_MAC "\x00\x00\x00\x00\x00\x00"
#define XCONF_XSOCK_SRV_PATH_0_GW  "\x00\x00\x00\x00\x00\x00"

#define XCONF_XSOCK_SRV_PATH_1_ITFC "enp1s0"
#define XCONF_XSOCK_SRV_PATH_1_ADDR_0 VPS_A
#define XCONF_XSOCK_SRV_PATH_1_ADDR_1 VPS_B
#define XCONF_XSOCK_SRV_PATH_1_ADDR_2 VPS_C
#define XCONF_XSOCK_SRV_PATH_1_ADDR_3 VPS_D
#define XCONF_XSOCK_SRV_PATH_1_MAC "\x00\x00\x00\x00\x00\x00"
#define XCONF_XSOCK_SRV_PATH_1_GW  "\x00\x00\x00\x00\x00\x00"

#define XCONF_XSOCK_SRV_PATH_2_ITFC "enp1s0"
#define XCONF_XSOCK_SRV_PATH_2_ADDR_0 VPS_A
#define XCONF_XSOCK_SRV_PATH_2_ADDR_1 VPS_B
#define XCONF_XSOCK_SRV_PATH_2_ADDR_2 VPS_C
#define XCONF_XSOCK_SRV_PATH_2_ADDR_3 VPS_D
#define XCONF_XSOCK_SRV_PATH_2_MAC "\x00\x00\x00\x00\x00\x00"
#define XCONF_XSOCK_SRV_PATH_2_GW  "\x00\x00\x00\x00\x00\x00"
