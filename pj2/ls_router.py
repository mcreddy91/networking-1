from sim.api import *
from sim.basics import *
import time

MAXINT = 99999
class LSRoutingUpdate(RoutingUpdate):
    def __init__(self):
        RoutingUpdate.__init__(self)
        self.timeStamp = time.time()

class LSRouter(Entity):
    
    def __init__(self):
        self.graph = {}
        self.neighbors = {}
        self.PortTable = {}
        self.RoutingTable = {}
        self.TimeStamps = {}

    def handle_rx(self, packet, port):
        if isinstance(packet, LSRoutingUpdate):
            if packet.src in self.TimeStamps.keys() and self.TimeStamps[packet.src] > packet.timeStamp:
                return
            if packet.src not in self.graph.keys() or self.graph[packet.src] != packet.paths:
                self.send(packet, flood=True)
                self.graph[packet.src] = packet.paths
                self.TimeStamps[packet.src] = packet.timeStamp
                self.create_new_RoutingTable()
                self.dij()

        elif isinstance(packet, DiscoveryPacket):
            timer=time.time()
            print "Discovery time",self,timer
            if packet.is_link_up:
                self.neighbors[packet.src] = 1
                self.PortTable[packet.src] = port
            else:
                del self.PortTable[packet.src]
                del self.RoutingTable[packet.src]
                del self.neighbors[packet.src]
                del self.graph[packet.src]
                for i in self.RoutingTable.keys():
                    if self.RoutingTable[i] not in self.neighbors.keys():
                        del self.RoutingTable[i]
            self.send_RoutingUpdate()

        else: #Forwarding packet
            if packet.dst in self.RoutingTable.keys():
                self.send(packet, self.PortTable[self.RoutingTable[packet.dst]])
       

    def send_RoutingUpdate(self):
        update_packet = LSRoutingUpdate()
        update_packet.src = self
        update_packet.paths = self.neighbors
        self.send(update_packet, flood=True)


    def dij(self):
        d = self.neighbors.copy()
        for i in d.keys():
            if i not in self.graph.keys():
                self.graph[i] = {}
            if self not in self.graph[i].keys():
                self.graph[i][self] = 1

        s = set()
        while s!=set(self.graph.keys()):
            min_d = MAXINT
            min_w = None
            for w in d.keys():
                if w not in s and d[w]<min_d:
                    min_d = d[w]
                    min_w = w
            if min_w is None:
                break
            s.add(min_w)
            if min_w in self.graph.keys():
                for i in self.graph[min_w].keys():
                    if i!=self and (i not in d.keys() or (i in self.graph[min_w].keys() and d[i] > d[min_w] + self.graph[min_w][i])):
                        d[i] = d[min_w] + self.graph[min_w][i]
                        self.RoutingTable[i] = min_w
      
        for i in self.RoutingTable.keys():
            p = self.RoutingTable[i]
            while p not in self.neighbors.keys():
                if p in self.RoutingTable.keys():
                    p = self.RoutingTable[p]
                else:
                    break;
            self.RoutingTable[i] = p
        

    def create_new_RoutingTable(self):
        self.RoutingTable = {}
        for i in self.neighbors.keys():
            self.RoutingTable[i] = i


