import sys
import getopt
import socket
import random
from collections import deque



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
    def start(self):
        seqno = 0
        msg_type = None
        while not msg_type=='end':
            msg=self.infile.read(1400)
            msg_type = 'data'
            if seqno == 0:
                msg_type = 'start'
            elif len(msg)< 1400:
                msg_type = 'end'
            self.helper(msg_type,seqno,msg)
            seqno += 1
            while (seqno <5):
                msg_type='data'
                msg=self.infile.read(1400)
                if len(msg) < 1400:
                    msg_type='end'
                    self.helper(msg_type,seqno,msg)
                    break
                self.helper(msg_type,seqno,msg)
                seqno +=1
            response = self.receive(0.50)
            self.handle_response(response)
        while(len(self.queue) !=0):
            response=self.receive(0.50)
            self.handle_response(response)
        self.infile.close()
        self.unacknowledge=0
        self.queue.clear()
    def handle_response(self,response):
        if (response==None):
            packet =self.queue.popleft()
            self.send(packet)
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
                self.queue.appendleft(packet)
                response=self.receive(0.50)
                self.handle_response(response)
            else:
                difference = int(seq)- self.unacknowledge
                while (difference >0):
                    self.unacknowledge +=1
                    self.queue.popleft()
                    difference -=1
                
    def helper(self, msg_type,seqno,msg):
        packet = self.make_packet(msg_type,seqno,msg)
        self.send(packet)
        self.queue.append(packet)
           
    
        

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
