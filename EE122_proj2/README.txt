Name: Shiyun Huang ee122-er
Partner: Yilin Liu ee122-hk

2.
Basically, the biggest challenge comes from handling the RoutingUpdates correctly.Especially the RIP router should handle the implicit withdrawal and poisoned-reverse differently and update the routing table and shortest paths accordingly. For implicit withdrawal, you need to make sure that when you remove a path base on the paths in the Routing Update packet, you don't remove your neighbor which sends the update packet. Because when a neighbor sends update,it won't include itself, but it doesn't mean that there is no path to the neighbor. For poison reverse, you need to make sure if the distance to a destination through you is 100, then you delete you path to the destination in your routing table or you don't add this path to your routing table(you "think" the path to the destionation is infinity. My routing table stores the destination as key and a list of paths to the destination as value. Each element of the path is also a list with the first element as the distance routing from a specific neighbor(which is the last element in the sublist). The second element of the sublist is the port number of the neighbor. Here is a trick, if I put the distance as the first element and port number as the second element. When I do sorted(),it will automatically sort the list in the way specified in the project spec, so I don't need to worry about sorting any more. My RIP router only sends update when the shortest distance to some destination changes. So I use a variable shortest_changed to keep track of this. The shortest distance to each destination is stored as a dictionary. The key is the destination while the value is a tuple which stores(shortest distance,port to send to).So everytime after sorting, if the port corresponding to the shortest distance changes, then the router needs to send RoutingUpdate.

I also use a port table to store the mapping between each neighbor and the port number. This is just for the convenience of iteration in sending RoutingUpdatesto neighbors. The self.not_add variable is specifically for handling a situation where there is destination in the routing table,and there is a new path to it and you need to add this new path to the path list of the destination. If it's false, then you can safely add it; or else,the path already exists and it's already updated. 

3. According to the lecture, a path vector will solve the count to infinity problem in RIP router. 


4. We did the first and second extra credit. The first extra credit is link_weights.txt and the second one is ls_router.py

The LSRouter is implemented using the Dijkstra's algorithm to calculate the shortest distance to each node and generate a routing table for it. Each LSRouter will keep track of its neighbors through DiscoveryPacket and send out the information about direct links through LSRoutingUpdate. Each time a router receives a LSRoutingUpdate packet it will update the topology stored in it and calculate the shortest distance using Dijkstra's algorithm and store the information in the routing table.After each router gets enough information of the full topology (aka. converges), the routing state will be stable.

We benchmark the convergence time in three scenarios and compare them(based on candy topology):
For RIP Router, the convergence time is the time when the last router's self.shortest_changed field is False(when it receives a RoutingUpdate but doesn't need to send any more Routing Update) minus the time when the first router receives a discovery packet.

For lSRouter, the convergence time is the time when the last router finishes running dijkstra's algorithm minus the time when the first router receives a discovery packet.

                  when the scenario is first set up(start())              Normally when a link is up or down            When there is count-to-infinity problem
                                                                                                                            in RIP Router
                                                
Linked State:       1.53secs.                                             Normally 1-2secs                                        1.42secs



RIP Router:         1.42secs                                             Normally 1.5-2secs                                       50.18secs


From the table above we could see, when the topology doesn't raise the count-to-infinity problem, LSRouter doesn't do much better than RIP Router;they are about the same. But when there is the count-to-infinity problem, LSRouter performs much better than RIPRouter.
