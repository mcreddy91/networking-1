Name:Shiyun Huang ee122-er
Partner: Yilin Liu 

Basic Sender Implementation:
In the basic sender, we implement a sliding window algorithm. Every time the send doesn't receive any ACK in 0.5s, it assume all the five packets it has transmitted are lost and therefore retransmit all the packets(Of course it may also be the ACKs are all lost, but anyway it's a lossy network, so just retransmit).

If we see the checksum of the ACK is corrupted or the reordered ACK is received, we just ignore it and  return to the main function and proceed. If there is a lost packet(assume the duplicate rate in the network is low), we just retransmit the lost packet. We maintain a queue of all sent packets and an instance variable self.unacknowledge to record the lowest number of unacknowledged packets for the sender. When a reordered ACK is received and its sequence number is higher than self.unacknowledge, then you know all the packets before this sequence number are all received by the receiver. So in this case you just pop off the acknowledged packets and send the same number of new  packets as number of the ones you pop off from the queue to the receiver.

Extra Credit 1(variable size window):
The sender will detect the network condition by calculating the loss rate of packets. The loss rate is based on resended packets/total packets in a specific time period. This rate will be refreshed after a certain time (i.e. 40 seconds). When the network is good (without too much loss of packets), the sender will increase the window size based on the rate; when it is bad the sender will decrease the window size based on the rate.

Extra Credit 2(selective acknowledgement):
Actually, in our basic implementation of sender, based on the calculation between the ACK sequence number and the instance variable it maintains for the lowest unacknowledged packet, it has already done selective acknowledgement. But having full information from receiver lets us know when there is a retransmission, what other packets in the window the sender could also send(which is currently not received by the receiver). So when the receiver receives the lost packet, it could gather full window of packets and move to the next window.

Extra Credit 3(round-trip time):
We find that the 500ms timeout is too long to wait. The actual roundtrip-time to receive an ack is much less than it. So we measure the roundtrip time by timing the interval between each ack. Each time we get a new interval, we will recalculate the timeout by averaging recent ack intervals (we have an array to record them). We also add an 15ms extra time to allow for timeout update so that the timeout may both increase or decrease based on the ack interval.
