import sys
import getopt
import socket
import random
from collections import deque



import Checksum
import BasicSenderSelective

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''


class Sender(BasicSenderSelective.BasicSender):
    
    def __init__(self,dest,port,filename,debug=False):
        BasicSenderSelective.BasicSender.__init__(self,dest,port,filename,debug=False)
        self.queue=deque()
        self.unacknowledge=0
        self.difference=0
    def start(self):
        seqno = 0
        msg_type = None
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
            while (self.difference >0 and msg_type !='end'):
                msg=self.infile.read(1400)
                if (len(msg) <1400):
                    msg_type='end'
                    self.helper(msg_type,seqno,msg)
                    break
                self.helper(msg_type,seqno,msg)
                seqno+=1
                self.difference -=1
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
            while (len(self.queue)!=0):
                packet =self.queue.popleft()
                self.send(packet)
                buffer.append(packet)
            while (len(buffer) !=0):
                packet=buffer.popleft()
                self.queue.append(packet)
            response = self.receive(0.50)
            self.handle_response(response)
        elif Checksum.validate_checksum(response)==False:
            return
        elif Checksum.validate_checksum(response):
            type1, seq ,seqno_list,checksum =self.split_packet(response)
            packet=self.queue.pop()
            self.queue.append(packet)
            type2, seq2, data ,checksum=self.split_packet(response)
            if int(seq)-1 < self.unacknowledge:
                if int(seq) < self.unacknowledge:
                    return
                l=seqno_list.split(' ')
                send_list=list()
                for x in range(self.unacknowledge,int(seq2)+1):
                    if x not in l:
                        send_list.append(x-self.unacknowledge)
                buffer=deque()
                for i in range(int(seq2)+1-self.unacknowledge):
                    packet=self.queue.popleft()
                    if i in send_list:
                        self.send(packet)
                    buffer.append(packet)
                while(len(buffer) != 0):
                    packet=buffer.pop()
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
