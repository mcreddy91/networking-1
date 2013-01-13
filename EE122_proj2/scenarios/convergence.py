import sim
from sim.core import CreateEntity, topoOf
from sim.basics import BasicHost
from rip_router import RIPRouter
from ls_router import LSRouter
import sim.topo as topo

def create (switch_type = RIPRouter, host_type = BasicHost):
    '''
              A---h1a
              |
              |
              B
             / \
            /   \
           C-----D--h1b
    '''
    switch_type.create('A')
    switch_type.create('B')
    switch_type.create('C')
    switch_type.create('D')
    host_type.create('h1a')
    host_type.create('h1b')
    topo.link(A,B)
    topo.link(B,C)
    topo.link(C,D)
    topo.link(B,D)
    topo.link(h1a,A)
    topo.link(h1b,D)
    C.OracleTable= {h1b: [[2, 1, D], [3, 0, B]], B : [[1, 0, B], [2, 1, D]], D: [[1, 1, D], [2, 0, B]]}





 










  

