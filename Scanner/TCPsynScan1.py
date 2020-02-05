#!/usr/bin/python
#import scapy
from scapy.all import *


conf.L3socket=L3RawSocket # for use loopback ip address in targetHost="127.0.0.1"
#def SynScan(Host,methodScan,ports):
def SynScan(Host,methodScan,StartPort,EndPort):
    OpenPort=[0]
    for Destport in range(StartPort,EndPort):
        a = IP(dst=Host)/TCP(dport= Destport ,flags=methodScan)
        ans , unans = sr(a)
        ans.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA",
            prn=lambda(s,r):OpenPort.append(Destport))
        #ans.summary()
    for i in OpenPort:
        if i>0 :
            print "open port "+str(i)


def main():
    targetHost="127.0.0.1"
    SynScan(targetHost,"S",79,81)


main()

"""

#Generate Packet
def GenPacket(Host,methodScan,StartPort,EndPort):
    OpenPort=[0]
    for Destport in range(StartPort,EndPort):
        packet = IP(dst=Host)/TCP(dport= Destport ,flags=methodScan)
    returen packet:


#Send Pacet
def SendPacket(packet):
    ans , unans = sr(packet)
    returen ans , unans
#Show Resulte
def ShowResulte(ans, unans):
    OpenPort=[0]
    ans.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA",
        prn=lambda(s,r):OpenPort.append(Destport))
    #ans.summary()
    for i in OpenPort:
    if i>0 :
        print "open port "+str(i)
def main()
    targetHost="127.0.0.1"
    packet = GenPacket(targetHost,"S",79,81)
    ans , unans =SendPacket(packet)
    ShowResulte(ans , unans)



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
