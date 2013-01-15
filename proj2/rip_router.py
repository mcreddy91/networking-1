from sim.api import *
from sim.basics import *
import time

'''
Create your RIP router in this file.
'''


class RIPRouter (Entity):
    def __init__(self):
        self.RoutingTable=dict()
        self.shortest=dict()
        self.shortest_changed=False
        self.PortTable=dict()
        self.not_add=False
        self.OracleTable=None
      
    def handle_rx (self, packet, port):
        if isinstance(packet,RoutingUpdate) ==False and isinstance(packet,DiscoveryPacket)==False:
            if packet.dst not in self.shortest:
                pass
            else:
                out_port=self.shortest[packet.dst][1]
                self.send(packet,out_port)
                
        else:
            if isinstance(packet,DiscoveryPacket):
                time_start=time.time()
                print "Discovery time",self,time_start
                if packet.is_link_up==True:
                    if packet.src not in self.RoutingTable:
                        self.RoutingTable[packet.src]=list() 
                    self.RoutingTable[packet.src].append([1,port,packet.src])
                    self.PortTable[packet.src]=port
                    self.shortest[packet.src]=(1,port)
                    self.shortest_changed=True
                   
                elif packet.is_link_up==False:
                    del self.PortTable[packet.src]
                    remove_entry=list()
                    for destination,path in self.RoutingTable.iteritems():
                        remove_item=list()
                        for pair in path:
                            if pair[2]==packet.src:
                                remove_item.append(pair)
                                break
                        for v in remove_item:
                            path.remove(v)
                        paths=sorted(path)
                        if len(paths)==0:
                            remove_entry.append(destination)
                            self.shortest_changed=True
                            del self.shortest[destination]
                        elif (destination not in self.shortest) or (paths[0][1] != self.shortest[destination][1]):
                            self.shortest_changed=True
                            self.shortest[destination]=(paths[0][0],paths[0][1])
                    for v in remove_entry:
                        del self.RoutingTable[v]
            elif isinstance(packet,RoutingUpdate):
                des=packet.all_dests()
                path_present=list()
                remove_entry=list()
                for destination,path in self.RoutingTable.iteritems():
                    if destination not in des and destination != packet.src:  
                        remove_item=list()
                        for pair in path:
                            if pair[2]==packet.src:                                    
                               remove_item.append(pair)
                               break
                        for v in remove_item:
                            path.remove(v)
                    elif destination in des:
                        remove_item=list()
                        for pair in path:
                            if pair[2]==packet.src:
                                distance=packet.get_distance(destination)
                                if distance !=100:
                                    pair[0]=1+packet.get_distance(destination)
                                    path_present.append(destination)
                                    self.not_add=True
                                    break
                                elif distance ==100:
                                    remove_item.append(pair)
                                    self.not_add=True
                                    break
                        for v in remove_item:
                            path.remove(v)
                        if self.not_add==False:
                            distance= packet.get_distance(destination)
                            if distance!=100:
                                path.append([1+distance,port,packet.src])
                                path_present.append(destination)
                        self.not_add=False       
                    paths=sorted(path) 
                    if len(paths)==0:
                        remove_entry.append(destination)
                        self.shortest_changed=True
                        del self.shortest[destination]
                    elif (destination not in self.shortest) or (paths[0][1] !=self.shortest[destination][1]):
                        self.shortest_changed=True                                    
                        self.shortest[destination]=(paths[0][0],paths[0][1])
                for v in remove_entry:
                    del self.RoutingTable[v]
                for d in des:   
                    if d==self:
                        pass
                    elif d not in path_present:
                        distance=packet.get_distance(d)
                        if distance !=100:
                            distance= 1+distance
                            self.RoutingTable[d]=[[distance,port,packet.src]]
                            self.shortest_changed=True
                            self.shortest[d]=(distance,port)
            if self.shortest_changed==True:
                for neighbor in self.PortTable.keys():
                    r=RoutingUpdate()
                    out_port=self.PortTable[neighbor]
                    for des,pair in self.shortest.iteritems():
                        if pair[1]==out_port:
                            if des != neighbor:
                                r.add_destination(des,100)
                            elif des == neighbor:
                                pass
                        else:
                            r.add_destination(des,pair[0])
                    self.send(r,out_port)     
                self.shortest_changed=False
            #print self.RoutingTable
            '''
            else:
                timer=time.time()
                print "convergence time",self,timer
            '''
            
            if self.OracleTable !=None:
                if (self.OracleTable==self.RoutingTable):
                    time_converge= time.time()
                    print "Convergence time",self,time_converge
                  
