import logging
import socket
import sys
from clientInit import BLTPClient
from serverInit import BLTPServer
import sock
import time
from bltp import BLTPConnection, State, BaseHeader, BLTPPacket, HeaderType, encode_variable_length, decode_variable_length, FinRstHeader


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # change to ERROR for production

class BLTPServer:
    def __init__(self):
        self.connections = []

    def listen(self, local_ip, local_port):
        self.address = local_ip
        self.port = local_port
        self.sock = sock.BLTPSocket(local_ip, local_port, True)
    
    def wait_for_con(self) -> tuple:
        self.sock.receive(('0.0.0.0', -1))

        for pos_new_con in self.sock.messages_received.keys():
            if not(pos_new_con in self.connections):
                return pos_new_con
        
    def check_for_fin(self, connection):
        connection.listen_for_fin()
    
    def accept(self, connection):
        if connection not in self.sock.messages_received.keys():
            return False

        connection = BLTPConnection(self.address, self.port, connection[0], connection[1], self.sock)
        connection.update_state(State.LISTEN)  
        self.connections.append(connection)
        connection.receive_handler()
        return connection
    
    def send(self, connection, message) -> int:
        if connection not in self.connections:
            return 0

        try:
            sent_data = connection.send(BLTPPacket(BaseHeader(connection.seq_num, connection.ack_num, 60, HeaderType.NO_HEADER), [], message)) # bytes(message, 'utf-8')
            return sent_data
        except KeyError as kerror:
            return 0
    
    def receive(self, connection, byte_count, timeout=None) -> bytes:
        if connection not in self.connections:
            return None

        max_time = time.time() + timeout if timeout is not None else 0
        self.sock.timeout(timeout)

        while len(connection.received_data) < byte_count and (timeout is None or time.time() < max_time):
            connection.receive_handler()

        received = connection.received_data[:byte_count]
        connection.received_data = connection.received_data[byte_count:]
        return received
    
    def check_for_closed(self, connection) -> bool:
        if connection.state == State.CLOSED:
            del self.connections[self.connections.index(connection)]
            return True
        return False

        