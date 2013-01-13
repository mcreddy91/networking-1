from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import*
import string
import re

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
    def __init__(self):
        self.tempPort={}
        self.serverCommand={}
        

    def _handle_ConnectionIn(self,event,flow,packet):
        
        if (flow.dstport >=0 and flow.dstport <=1023):
            event.action.forward=True
            if flow.dstport ==21:
                event.action.monitor_forward=True
                event.action.monitor_backward=True
                mapping=(flow.src,flow.srcport,flow.dst,flow.dstport)
                self.serverCommand[mapping]=''
            return
        p_mapping=(flow.dst,flow.dstport)
        if (p_mapping in self.tempPort):    
            timerList=self.tempPort[p_mapping]
            if len(timerList)>0:
                timer=timerList.pop(0)
                timer.cancel()
                event.action.forward=True
            if len(timerList)==0:
                del self.tempPort[p_mapping]
        else:
            event.action.deny=True
            
    def _handle_teardown(self,p_mapping):
        timerList=self.tempPort[p_mapping]
        timerList.pop(0)
        if len(timerList)==0:
            del self.tempPort[p_mapping]


 
    def _handle_DeferredConnectionIn(self,event,flow,packet):
        pass


    def _handle_MonitorData(self,event,packet,reverse):
        ipv4_packet=packet.payload
        tcp_packet=ipv4_packet.payload
        data_packet=tcp_packet.payload
        mapping = (ipv4_packet.srcip,tcp_packet.srcport,ipv4_packet.dstip,tcp_packet.dstport)
        if mapping not in self.serverCommand:
            mapping=(ipv4_packet.dstip,tcp_packet.dstport,ipv4_packet.srcip,tcp_packet.srcport)
        if mapping in self.serverCommand:
            if data_packet != '':
                if reverse==True:
                    data_packet=self.serverCommand[mapping]+data_packet
                    last_match=data_packet.rfind('\n')+1
                    payload=data_packet[:last_match]
                    data_packet=data_packet[last_match:]
                    self.serverCommand[mapping]=data_packet
                    b=payload.split('\n')
                    if len(b)>1:
                        for message in b:
                            if  len(message) >=4 and message[:4]=="227 ":
                                #f=re.findall(r'\(\d+,\d+,\d+,\d+,\d+,\d+\)\.?\r?',message)
                                f=[(m.start(0),m.end(0)) for m in re.finditer(r'\(\d+,\d+,\d+,\d+,\d+,\d+\)\.?\r?',message)]
                                if len(f)>0 and f[-1][1]==len(message):
                                    g=message[f[-1][0]:]
                                    log.debug("227 "+str(g))
                                    g=g[1:]
                                    g=g[:g.find(')')]
                                    l=g.split(',')
                                    h=[int (a) for a in l]
                                    negative=False
                                    for a in h:
                                        if a <0:
                                            negative =True
                                            break
                                    if negative ==False:
                                        newPort= h[-2]*256 + h[-1]
                                        l.pop(-2)
                                        l.pop(-1)
                                        h.pop(-2)
                                        h.pop(-1)
                                        invalid = False
                                        for a in h:
                                            if a <0 or a > 255:
                                                invalid=True
                                                break
                                        if invalid==False and newPort <=65535 and newPort >1023 :
                                            addr='.'.join(l)
                                            addr=IPAddr(addr)
                                            log.debug("IPAddr :"+str(addr))
                                            log.debug("ipv4_packet source :"+str(ipv4_packet.srcip))
                                            p_mapping=(addr,newPort)
                                            timer=Timer(10,self._handle_teardown,args=[p_mapping])
                                            if p_mapping not in self.tempPort:
                                                self.tempPort[p_mapping]=[timer]
                                            else:
                                                self.tempPort[p_mapping].append(timer)
                            if len(message) >=4 and message[:4]=="229 ":
                                #f=re.findall(r'\(\|\|\|\d+\|\)\.?\r?',message)
                                f=[(m.start(0),m.end(0)) for m in re.finditer(r'\(\|\|\|\d+\|\)\.?\r?',message)]
                                if len(f)>0 and f[-1][1]==len(message):
                                    g=message[f[-1][0]:]
                                    g=g[4:]
                                    g=g[:g.find('|')]
                                    newPort=int(g)
                                    if newPort <=65535 and newPort >1023:
                                        addr=mapping[2]
                                        p_mapping=(addr,newPort)
                                        timer=Timer(10,self._handle_teardown,args=[p_mapping])
                                        if p_mapping not in self.tempPort:
                                            self.tempPort[p_mapping]=[timer]
                                        else:
                                            self.tempPort[p_mapping].append(timer)

            else:
                if tcp_packet.flags== 0x01 or tcp_packet.flags ==0x011 or tcp_packet.flags==0x014 or tcp_packet.flags==0x04:
                    del self.serverCommand[mapping]



