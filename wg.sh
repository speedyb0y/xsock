#!/bin/bash

ip link set dev cloudflare-isp up
ip link set dev cloudflare up

ip -4 addr add dev eth0 192.168.1.20/24
ip -4 addr add dev eth0 192.168.1.25/24
ip -4 addr add dev cloudflare 172.16.0.2
ip -4 addr add dev cloudflare-1 172.16.0.2
ip -4 addr add dev cloudflare-2 172.16.0.2
ip -4 addr add dev cloudflare-3 172.16.0.2
ip -4 addr add dev cloudflare-isp 192.168.1.25

ip -4 rule flush
ip -4 rule add priority 300 table main

ip -4 route flush table main
ip -4 route flush dev eth0
ip -4 route flush dev cloudflare
ip -4 route flush dev cloudflare-isp
ip -4 route flush dev cloudflare-1
ip -4 route flush dev cloudflare-2
ip -4 route flush dev cloudflare-3

ip -4 route add metric 1 dev eth0 192.168.1.0/24 src 192.168.1.20
ip -4 route add metric 1 dev cloudflare default src 172.16.0.2
ip -4 route add metric 1 dev cloudflare-isp 162.159.192.1 src 192.168.1.25
ip -4 route add metric 2 unreachable 162.159.192.1

wg set cloudflare-1 listen-port 5111 fwmark 0
wg set cloudflare-2 listen-port 5222 fwmark 0
wg set cloudflare-3 listen-port 5333 fwmark 0
