import logging
import sys
import sock
import time
from bltp import BLTPConnection, State, BaseHeader, BLTPPacket, HeaderType, FinRstHeader, HandshakeHeader


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # change to ERROR for production

class BLTPClient:
    def __init__(self, address="127.0.0.1", port=12345):
        self.address = address
        self.port = port

    def connect(self, server_address, server_port) -> sock:
        self.sock = sock.BLTPSocket(self.address, self.port, False)
        self.connection = BLTPConnection(self.address, self.port, server_address, server_port, self.sock)

        # send Handshake
        base_header = BaseHeader(0, 0, 60, HeaderType.HANDSHAKE)
        handshake_packet = BLTPPacket(base_header, [HandshakeHeader(0, HeaderType.NO_HEADER, 1140)], None)
        self.connection.send(handshake_packet)
        self.connection.seq_num += 1 # increment seq_num
        self.connection.update_state(State.CLIENT_INIT)
        logging.debug(f"Handshake packet sent\n")

        self.connection.receive_handler()

        return self.sock
    
    def send(self, message) -> int:
        try:
            sent_data = self.connection.send(BLTPPacket(BaseHeader(self.connection.seq_num, self.connection.ack_num, 60, HeaderType.NO_HEADER), [], message)) # bytes(message, 'utf-8')
            return sent_data
        except KeyError as kerror:
            logging.error("An error occured while sending the message")
            return 0
    
    def receive(self, byte_count, timeout=None) -> bytes:
        max_time = time.time() + timeout if timeout is not None else 0
        self.sock.timeout(timeout)

        while len(self.connection.received_data) < byte_count and (timeout is None or time.time() < max_time):
            self.connection.receive_handler()

        received = self.connection.received_data[:byte_count]
        self.connection.received_data = self.connection.received_data[byte_count:]
        return received
    
    def close(self):
        base_header_FIN = BaseHeader(self.connection.seq_num, self.connection.ack_num, 60, HeaderType.FIN_RST)
        fin_packet = BLTPPacket(base_header_FIN, [FinRstHeader(0, HeaderType.NO_HEADER, None, None)], None)
        self.connection.send(fin_packet)
        self.connection.seq_num += 1 # increment seq_num
        self.connection.update_state(State.CLOSE_WAIT)
        logging.debug(f"FIN packet sent\n")
        print(f"send with seq_num: {self.connection.seq_num}")
        print(f"send with ack_num: {self.connection.ack_num}")
        self.connection.receive_handler()

        self.sock = None
        