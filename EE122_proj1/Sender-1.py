import sys
import getopt
import socket
import random
from collections import deque
import time


import Checksum
import BasicSender

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''


class Sender(BasicSender.BasicSender):
    
    def __init__(self,dest,port,filename,debug=False):
        BasicSender.BasicSender.__init__(self,dest,port,filename,debug=False)
        self.queue=deque()
        self.unacknowledge=0
        self.difference=0
        self.timer = 0
        self.total_packets=0
        self.resend_packets=0
    def start(self):
        seqno = 0
        msg_type = None
        self.timer=time.time()
        while not msg_type=='end':
            while (seqno <5):
                msg_type='data'
                msg=self.infile.read(1400)
                if seqno == 0:
                    msg_type = 'start'
                elif len(msg)< 1400:
                    msg_type = 'end'
                    self.helper(msg_type,seqno,msg)
                    break
                self.helper(msg_type,seqno,msg)
                seqno +=1
            i=self.difference+self.detect_network()
            if (i<=0):
                i=1
            while (i >0 and msg_type !='end'):
                msg=self.infile.read(1400)
                if (len(msg) <1400):
                    msg_type='end'
                    self.helper(msg_type,seqno,msg)
                    break
                self.helper(msg_type,seqno,msg)
                seqno+=1
                i-=1
            self.difference=0
            response = self.receive(0.50)
            self.handle_response(response)
        while(len(self.queue) !=0):
            response=self.receive(0.50)
            self.handle_response(response)
        self.infile.close()
        self.unacknowledge=0
        self.difference=0
        self.queue.clear()
    def handle_response(self,response):
        if (response==None):
            buffer=deque()
            i=len(self.queue)+self.detect_network()
            if (i<=0):
                i=1
            j=min(len(self.queue), i)
            while (j > 0):
                packet =self.queue.popleft()
                self.send(packet)
                self.resend_packets+=1
                self.total_packets+=1
                buffer.append(packet)
                j-=1
            while (len(buffer) !=0):
                packet=buffer.pop()
                self.queue.appendleft(packet)
            response = self.receive(0.50)
            self.handle_response(response)
        elif Checksum.validate_checksum(response)==False:
            return
        elif Checksum.validate_checksum(response):
            type1, seq ,data,checksum =self.split_packet(response)
            if int(seq)-1 < self.unacknowledge:
                if int(seq) < self.unacknowledge:
                    return
                packet=self.queue.popleft()
                self.send(packet)
                self.resend_packets+=1
                self.total_packets+=1
                self.queue.appendleft(packet)
                response=self.receive(0.50)
                self.handle_response(response)
            else:
                self.difference = int(seq)- self.unacknowledge
                d=self.difference
                while (d >0):
                    self.unacknowledge +=1
                    self.queue.popleft()
                    d -=1
    def helper(self, msg_type,seqno,msg):
        packet = self.make_packet(msg_type,seqno,msg)
        self.send(packet)
        self.queue.append(packet)
        self.total_packets+=1
                   
    def detect_network(self):
        loss_rate = self.resend_packets*1.0/self.total_packets
        now = time.time()
        if (now-self.timer)>10:
            self.total_packets = 1
            self.resend_packets = 0
            self.timer = time.time()
        if loss_rate<0.3 and loss_rate>0:
            return 2
        if loss_rate>0.3 and loss_rate<0.5:
            return 1
        if loss_rate>0.75:
            return -1
        return 0         
 
    def strPacketInfo(self, packet):
        if (packet != None) and (not self.print_data):
            msg_type, seqno, data, checksum = self.split_packet(packet)
            return "%s|%d||%s" %(msg_type,int(seqno),checksum)
        return str(packet)      
    
        

'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        print "BEARS-TP Sender"
        print "-f FILE | --file=FILE The file to transfer; if empty reads from STDIN"
        print "-p PORT | --port=PORT The destination port, defaults to 33122"
        print "-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost"
        print "-d | --debug Print debug messages"
        print "-h | --help Print this usage message"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:d", ["file=", "port=", "address=", "debug="])
    except:
        usage()
        exit()

    port = 33122
    dest = "localhost"
    filename = None
    debug = False

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True

    s = Sender(dest,port,filename,debug)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
