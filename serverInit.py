# serverInit.py

from bltp import BLTPConnection, State, BaseHeader, BLTPPacket, HeaderType, encode_variable_length, decode_variable_length
import sys
import logging

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # change to ERROR for production or DEBUG for debug

class BLTPServer:
    def __init__(self, address, port, peer_address, peer_port, sock):
        self.address = address
        self.port = port
        self.peer_address = peer_address
        self.peer_port = peer_port
        self.connection = BLTPConnection(self.address, self.port, peer_address, peer_port, sock)

    def start(self):
        """self.connection.socket.bind((self.address, self.port))
        self.connection.socket.settimeout(2)"""
        self.connection.update_state(State.LISTEN)
        
        """while True:
            packet = self.connection.receive_handler()
            if self.connection.peer_port != -1:
                self.peer_address = self.connection.peer_address
                self.peer_port = self.connection.peer_port
                return packet
            if self.connection.state == State.ESTABLISHED:
                logging.debug(f"Connection established\n")
                return
            if self.connection.state == State.EOF:
                logging.debug(f"FIN received, sending ACK\n")
                # Send ACK for the received FIN
                base_header_ACK = BaseHeader(1, 2, 60, HeaderType.FIN_RST)
                ack_packet = BLTPPacket(base_header_ACK, [], None)
                self.connection.send(ack_packet)
                self.connection.update_state(State.EOF_WAIT)"""

def start_server():
    #server = BLTPServer('134.61.140.129', 54321, '127.0.0.1', 12345)
    server = BLTPServer('127.0.0.1', 54321, '127.0.0.1', 12345)
    server.start()

"""if __name__ == "__main__":
    server_thread = threading.Thread(target=start_server)
    server_thread.start()"""