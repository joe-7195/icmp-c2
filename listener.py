#!/usr/bin/env python3
from socket import *
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP
import json

if __name__ == '__main__':
    s: SocketType = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
    s.setsockopt(SOL_IP, IP_HDRINCL , 1)
    try:
        while True:
            recv = s.recvfrom(1024)
            b = recv[0]
            address = recv[1]

            p: Packet = IP(b)
            if p.haslayer(ICMP):
                body = json.loads(p.json())['payload']['payload']['load']
                print(body)

                src = p.src
                p.src = p.dst
                p.dst = src

                p[ICMP].type = 0
                p[ICMP].chksum = None
                p[ICMP].load = b'fortnite'
                b = bytes(p)

                s.sendto(b, address)
            
    except KeyboardInterrupt:
        s.close()