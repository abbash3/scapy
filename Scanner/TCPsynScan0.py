#!/usr/bin/python
#import scapy
from scapy.all import *


conf.L3socket=L3RawSocket # for use loopback ip address in targetHost="127.0.0.1"
#def SynScan(Host,methodScan,ports):
def SynScan(Host,methodScan,StartPort,EndPort):
    portOpen=[0]
    for Destport in range(StartPort,EndPort):
        a = IP(dst=Host)/TCP(dport= Destport ,flags=methodScan)
        ans , unans = sr(a)
        ans.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA",prn=lambda(s,r):portOpen.append(Destport))
    for i in portOpen:
        if i>0 :
            print "open port "+str(i)


def main():
    targetHost="127.0.0.1"
    SynScan(targetHost,"SA",79,82)


main()

"""
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
None
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
open port 80

Process returned 0 (0x0)	execution time : 0.548 s
Press [ENTER] to continue...
"""
