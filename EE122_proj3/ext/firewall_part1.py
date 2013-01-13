from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import*
import string
import os
import re
# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  
  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    log.debug("Firewall initialized.")
    self.banned_ports=[port.strip() for port in open('/root/pox/ext/banned-ports.txt','r')]
    self.banned_domains=[domain.strip() for domain in open('/root/pox/ext/banned-domains.txt','r')]
    self.monitor_string_pairs=[string_pair.strip() for string_pair in open('/root/pox/ext/monitored-strings.txt','r')]
    self.monitor_addresses=list()
    self.monitor_strings=list()
    for string_pair in self.monitor_string_pairs:
      pair_list=string_pair.split(':')
      self.monitor_addresses.append(pair_list[0])
      self.monitor_strings.append(pair_list[1])
    self.monitor_list={}
    self.occurrence_list={}
    self.not_banned=False
    self.f=open("/root/pox/ext/counts.txt","w")
    self.timer_list={}
    self.trail_holder_forward={}
    self.trail_holder_backward={}
   
   
    

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    mapping=(flow.src,flow.srcport,flow.dst,flow.dstport)
    if str(flow.dstport) in self.banned_ports:
      event.action.deny=True
      log.debug("denied connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
    else:
      event.action.defer=True
      log.debug("deferred connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
      if mapping in self.monitor_list:
        self.timer_list[mapping].cancel()
        self._handle_teardown(mapping)
       

  def _handle_teardown(self,mapping):
    iter=len(self.monitor_list[mapping])
    for x in range(iter):
      account=string.join([str(mapping[2]),str(mapping[3]),str(self.monitor_list[mapping][x]),str(self.occurrence_list[mapping][x])],',')
      self.f.write(account+"\n")
      self.f.flush()             
      os.fsync(self.f.fileno())
    del self.timer_list[mapping]
    del self.monitor_list[mapping]
    del self.occurrence_list[mapping]
    del self.trail_holder_forward[mapping]
    del self.trail_holder_backward[mapping]
    
   

  def _handle_DeferredConnectionIn (self, event, flow, packet):
    """
    Deferred connection event handler.
    If the initial connection handler defers its decision, this
    handler will be called when the first actual payload data
    comes across the connection.
    """
   
    http_packet=packet.payload.payload.payload
    log.debug("http data"+http_packet)
    if http_packet.find("HTTP/1.1")==-1:
      event.action.forward=True
    else:
      lowest_index=http_packet.find('Host: ')+6
      substring=http_packet[lowest_index:]
      highest_index=substring.find("\n")
      substring=substring[:highest_index]
      if substring[-1]=="\r":
        substring=substring[:-1]
      domain=substring
      split_domain=domain.split('.')
      split_domain.reverse()
      if ":" in split_domain[0]:
        index =split_domain[0].find(":")
        split_domain[0]=split_domain[0][0:index]
      domain_length=len(split_domain)
      for banned_domain in self.banned_domains:
        split_banned=banned_domain.split('.')
        split_banned.reverse()
        banned_length=len(split_banned)
        iter=min(banned_length,domain_length)
        for x in range(iter):
          if split_domain[x]!=split_banned[x]:
            self.not_banned=True
            break
        if self.not_banned==True:
          self.not_banned=False
        else:
          if banned_length <= domain_length:
            event.action.deny=True
            return
      event.action.forward=True
    if event.action.forward==True:
      if str(flow.dst) in self.monitor_addresses:
        event.action.monitor_forward=True
        event.action.monitor_backward=True
        mapping=(flow.src,flow.srcport,flow.dst,flow.dstport)
        log.debug("monitored connection :"+str(mapping))
        iter=len(self.monitor_addresses)
        self.monitor_list[mapping]=list()
        for x in range(iter):
          if self.monitor_addresses[x]==str(flow.dst):
            self.monitor_list[mapping].append(self.monitor_strings[x])
        length=len(self.monitor_list[mapping])
        self.occurrence_list[mapping]=[0]*length
        self.timer_list[mapping]=Timer(30,self._handle_teardown,args=[mapping])
        self.trail_holder_backward[mapping]={}
        self.trail_holder_forward[mapping]={}
   
    
  def _handle_MonitorData (self, event, packet, reverse):
    """
    Monitoring event handler.
    Called when data passes over the connection if monitoring
    has been enabled by a prior event handler.
    """
    ipv4_packet=packet.payload
    tcp_packet=ipv4_packet.payload
    data_packet=tcp_packet.payload
    mapping = (ipv4_packet.srcip,tcp_packet.srcport,ipv4_packet.dstip,tcp_packet.dstport)
    if mapping not in self.monitor_list:
      mapping=(ipv4_packet.dstip,tcp_packet.dstport,ipv4_packet.srcip,tcp_packet.srcport)
    if mapping in self.monitor_list:
      if data_packet != '':
        log.debug("http data" +data_packet)
        self.timer_list[mapping].cancel()
        for count,search_string in enumerate(self.monitor_list[mapping]):
          search_length=len(search_string)
          http_packet=data_packet
          if reverse==True:
            if search_string in self.trail_holder_backward[mapping]:
              http_packet=self.trail_holder_backward[mapping][search_string]+http_packet
            packet_length=len(http_packet)
            if search_length <= packet_length:
              findings=[(m.start(0),m.end(0)) for m in re.finditer(search_string,http_packet)]
              if search_length !=1:
                tail2=http_packet[(search_length-1)*(-1):]
              else:
                tail2=''
              if len(findings) !=0:
                occurrence=http_packet.count(search_string)
                self.occurrence_list[mapping][count]+=occurrence
                last_match_backward=findings[-1][1]-1
                tail1=http_packet[(packet_length-1-last_match_backward)*(-1):]
                if last_match_backward == packet_length-1:
                  self.trail_holder_backward[mapping][search_string]=''
                else:
                  if len(tail1)>len(tail2):
                    self.trail_holder_backward[mapping][search_string]=tail2
                  else:
                    self.trail_holder_backward[mapping][search_string]=tail1
              else:
                self.trail_holder_backward[mapping][search_string]=tail2
            else:
              self.trail_holder_backward[mapping][search_string]=http_packet

          else:
            if search_string in self.trail_holder_forward[mapping]:
              http_packet=self.trail_holder_forward[mapping][search_string]+http_packet
            packet_length=len(http_packet)
            if search_length <= packet_length:
              findings=[(m.start(0),m.end(0)) for m in re.finditer(search_string,http_packet)]
              if search_length !=1:
                tail2=http_packet[(search_length-1)*(-1):]
              else:
                tail2=''
              if len(findings) !=0 :
                occurrence=http_packet.count(search_string)
                self.occurrence_list[mapping][count]+=occurrence
                last_match_forward=findings[-1][1]-1
                tail1=http_packet[(packet_length-1-last_match_forward)*(-1):]
                if last_match_forward == packet_length-1:
                  self.trail_holder_forward[mapping][search_string]=''
                else:
                  if len(tail1)> len(tail2):
                    self.trail_holder_forward[mapping][search_string]=tail2
                  else:
                    self.trail_holder_forward[mapping][search_string]=tail1
              else:
                 self.trail_holder_forward[mapping][search_string]=tail2
            else:
              self.trail_holder_forward[mapping][search_string]=http_packet

        self.timer_list[mapping]=Timer(30,self._handle_teardown,args=[mapping])
      

 
