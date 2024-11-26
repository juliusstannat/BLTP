#clientInit.py

import threading
from bltp import BLTPConnection, State, BaseHeader, BLTPPacket, HeaderType, encode_variable_length, decode_variable_length, HandshakeHeader
import logging
import logging
import sys


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # change to ERROR for production or DEBUG for debug


class BLTPClient:
    def __init__(self, address, port, server_address, server_port, sock):
        self.connection = BLTPConnection(address, port, server_address, server_port, sock)

    def start(self):
        """self.connection.socket.bind((self.connection.address, self.connection.port))
        self.connection.socket.settimeout(2)"""
        
        # Sende Handshake 
        base_header = BaseHeader(0, 0, 60, HeaderType.HANDSHAKE)
        handshake_packet = BLTPPacket(base_header, [HandshakeHeader(0, HeaderType.NO_HEADER, 1140)], None)
        self.connection.send(handshake_packet)
        self.connection.update_state(State.CLIENT_INIT)
        logging.debug(f"Handshake packet sent\n")
        
        return
        while True:
            return
            self.connection.receive_handler()
            if self.connection.state == State.ESTABLISHED:
                logging.debug(f"Connection established\n")
                return
                # Send FIN to close the connection
                #self.connection.enable_encryption() TODO

                # Send test data

                self.connection.send(BLTPPacket(BaseHeader(1, 1, 60, HeaderType.NO_HEADER), [], b"Hello World!"))

                
                base_header_FIN = BaseHeader(1, 1, 60, HeaderType.FIN_RST)
                fin_packet = BLTPPacket(base_header_FIN, [], None)
                self.connection.send(fin_packet)
                self.connection.update_state(State.CLOSE_WAIT)
                logging.debug(f"FIN packet sent\n")
          

def start_client():
    #client = BLTPClient('134.61.140.129', 12345, '134.61.75.9', 54321)
    client = BLTPClient('127.0.0.1', 12345, '127.0.0.1', 54321)
    client.start()

"""if __name__ == "__main__":
    client_thread = threading.Thread(target=start_client)
    client_thread.start()"""