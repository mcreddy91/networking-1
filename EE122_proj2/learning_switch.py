from sim.api import *
from sim.basics import *

'''
Create your learning switch in this file.
'''
class LearningSwitch(Entity):
    def __init__(self):
        self.portDict= dict()
        
    def handle_rx (self, packet, port):
        
        if (packet.dst not in self.portDict):
            self.send(packet,port,flood=True)
        else:
            portDst=self.portDict[packet.dst]
            self.send(packet,portDst,flood=False)
        self.portDict[packet.src]=port
