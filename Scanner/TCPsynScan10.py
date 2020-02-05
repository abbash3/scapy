#!/usr/bin/python
#import scapy
from scapy.all import *
conf.L3socket=L3RawSocket # for use loopback ip address in targetHost="127.0.0.1"
#def SynScan(Host,methodScan,ports):

#Generate Packet
def GenPacket(Host,methodScan,StartPort,EndPort):
    OpenPort=[0]
    #packet= IP()
    #for Destport in range(StartPort,EndPort):
    #    packet = IP(dst=Host)/TCP(dport= Destport ,flags=methodScan)
    #if methodScan=="S":
    packet = IP(dst=Host)/TCP(dport= (StartPort,EndPort) ,flags=methodScan)
    #packet.show2()
    return packet

#Send Packet
def SendPacket(methodScan,targetHost,packet):
        #ans , unans = sr(IP(dst="127.0.0.1"))
        #if methodScan=="S":
        ans , unans = sr(packet,verbose=1,timeout=4)
        #ans.summary()
        ShowResulte(methodScan,targetHost,ans,unans)
    #return ans , unans
#Show Resulte
def ShowResulte(methodScan,targetHost,ans, unans):
    #ans.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA"),prn=lambda(s,r):r.sprintf("%TCP.sport% is open")
    if (ans or unans) :
        if methodScan =="S" :
                print "The Host " +targetHost+ " is up"
                ans.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA",prn=lambda(s,r):r.sprintf("%TCP.sport% is open"))
                #ans.summary()
        if methodScan =="SA" : #This is a Syn Ack Scan
                print "The Host " +targetHost+ " is up"
                #ans.summary()
                #print "unans-------------------------"
                #unans.summary()
        if methodScan =="A" :  #This is a Ack Scan
                print "The Host " +targetHost+ " is up"
                #ans.summary()
                #print "unans-------------------------"
                #unans.summary()
#        if methodScan ==" " : #This is Tcp Null Scan
#                print "The Host " +targetHost+ " is up"
                #ans.summary()
                #print "unans-------------------------"
                #unans.summary()
        if methodScan =="FPU" : #This is Tcp XMAS scan
                print "The Host " +targetHost+ " is up"
                #uans.summary(lfilter = lambda (s,r): s.sprintf("%TCP.flags%") == "FPU",prn=lambda(s,r):s.sprintf("%TCP.sport% is open"))

                #ans.summary()
                #print "unans-------------------------"
                #unans.summary(lfilter = lambda (s,r): s.sprintf("%TCP.flags%"))

def FlagScan(targetHost,methodScan,StartPort,EndPort):
    packet = GenPacket(targetHost,methodScan,StartPort,EndPort)
    SendPacket(methodScan,targetHost,packet)
def main():
    targetHost="192.168.18.128"
    FlagScan(targetHost,"FPU",21,23)



main()



"""
The TCP SYN Scan
The Host 192.168.18.128 is up
ssh is open
http is open
The Scan Method for  Host Discovry is 'TCP SYN + ACK'
The Host 192.168.18.128 is up

Process returned 0 (0x0)	execution time : 0.561 s
Press [ENTER] to continue...
"""
