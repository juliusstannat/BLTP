import socket
#import queue

class BLTPSocket:
    def __init__(self, address, port, server=False):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, port))
        #self.socket.settimeout(2)
        self.server = server
        self.messages_received = {}
        self.address = address
        self.port = port


    """def start(address, port):
        socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket.bind((address, port))
        socket.settimeout(2)"""
    
    def send(self, packet, address, port):
        self.socket.sendto(packet, (address, port))

    def receive_temp(self, address, bufsize=1024):
        self.socket.settimeout(2)
        try:
            data, addr = self.socket.recvfrom(bufsize)
            #print(f"received {data} from {addr}")

            if self.messages_received.get(addr) == None:
                self.messages_received[addr] = [data]
                #self.messages_received[addr].append(data)
            else:
                self.messages_received[addr].append(data)
            
            
        except socket.timeout:
            pass
        self.socket.settimeout(None)

        return self.messages_received[address]



    def receive(self, address, bufsize=1024):
        if self.messages_received.get(address) is not None:
            if len(self.messages_received[address]) > 0:
                res = self.messages_received[address].pop(0)
                if len(self.messages_received[address]) == 0:
                    del self.messages_received[address]
                return res

        try:
            data, addr = self.socket.recvfrom(bufsize)
            #print(f"received {data} from {addr}")

            if self.messages_received.get(addr) == None:
                self.messages_received[addr] = [data]
                #self.messages_received[addr].append(data)
            else:
                self.messages_received[addr].append(data)
        except socket.timeout:
            pass
        
        if self.messages_received.get(address) == None:
            return None
        if len(self.messages_received[address]) == 0:
            return None
        
        res = self.messages_received[address].pop(0)

        if len(self.messages_received[address]) == 0:
            del self.messages_received[address]

        return res
        
        
    
    def close(self):
        if not self.server:
            self.socket.close()
    
    def timeout(self, timeout):
        self.socket.settimeout(timeout)

