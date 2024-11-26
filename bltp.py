#bltpForm.py stellt definiert das Protokoll 
from enum import Enum
#import socket
import logging
import sys
import time 
from typing import Tuple
import struct
import threading
from collections import deque
import random

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # change to ERROR for production or DEBUG for debug



# ------------------------------------- Kapitel 2: Packets -------------------------------------

class HeaderType(Enum):
    NO_HEADER = 0
    HANDSHAKE = 1
    FIN_RST = 2
    ENCRYPTION = 1140


# definiere Base-Header, wobei die Struktur nach RFC ist
class BaseHeader:
    def __init__(self, seq_num: int, ack_num: int, rcv_window: int, next_header: HeaderType):
        self.seq_num = seq_num # 32 number
        self.ack_num = ack_num # 32 number
        self.rcv_window = rcv_window # i number
        self.next_header = next_header # i number


# definiere Extension-Header
class ExtensionHeader:
    def __init__(self, length, next_header: HeaderType, specific_data: None):
        self.length = length    #in number of bytes
        self.specific_data = specific_data
        self.next_header = next_header



class HandshakeHeader(ExtensionHeader):
    def __init__(self, length, next_header, supported_headers):
        super().__init__(length, next_header, None)
        self.supported_headers = supported_headers


# "none" - soll Optionalität gewaehrleisten
class FinRstHeader(ExtensionHeader):
    def __init__(self, length, next_header, error_code=None, error_message=None):
        super().__init__(length, next_header, None)
        self.error_code = error_code
        self.error_message = error_message

    def is_fin(self):
        return self.error_code is None or self.error_code == b'' or self.error_code == 0

    def is_rst(self):
        return self.error_code is not None and self.error_code != b'' and self.error_code != 0





## -------------------------------------------- encoding und decoding --------------------------------------------   



# Fixed-Size Integer Fields
def encode_fixed_size(data, size):
    if size == 8:
        # Encode data als ein 8-bit unsigned integer 
        return struct.pack('!B', data)  
    elif size == 16:
        # Encode data als ein 16-bit unsigned integer  
        return struct.pack('!H', data)  
    elif size == 24:
        # Encode data als erstes in ein 4-byte (32-bit, big-endian order) unsigned integer 
        # Dann wird das erste byte gescliced, sodass 3 bytes (24-bits) uebrig bleiben
        return struct.pack('!I', data)[1:] 
    elif size == 32:
        # Encode data als ein 32-bit unsigned integer 
        return struct.pack('!I', data)
    else:
        raise ValueError("Unsupported size")
    

def decode_fixed_size(data, size):
    #size = len(data)
    if size == 8:
        # Dekodiere von einem 8-bit unsigned integer 
        # Analog bei den anderen Faellen
        return struct.unpack('!B', data[:1])[0]
    elif size == 16:
        return struct.unpack('!H', data[:2])[0]
    elif size == 24:
        return struct.unpack('!I', b'\x00' + data[:3])[0]
    elif size == 32:
        return struct.unpack('!I', data[:4])[0]
    else:
        raise ValueError("Unsupported size")



# Variable-Length Integer Fields
# nach RFC Dokumentation 
def encode_variable_length(data):
    if isinstance(data, HeaderType):
        data = data.value
    if data <= 0x3F:
        # 6-Bit-Wert, der in einem Byte passt
        #print(struct.pack('!B', data))
        return struct.pack('!B', data)
    elif data <= 0x3FFF:
        # 14-Bit-Wert, der in zwei Bytes passt
        return struct.pack('!H', 0x4000 | data)
    elif data <= 0x3FFFFF:
        # 22-Bit-Wert, der in drei Bytes passt
        #slicing auf 3 Bytes, um die führenden (8) 0-len zu elimieren 
        return struct.pack('!I', 0x800000 | data)[1:]
    else:
        # 30-Bit-Wert, der in vier Bytes passt
        return struct.pack('!I', 0xC0000000 | data)



# Decode bzw unpack von Variable length Integer Fields
# returnes (Bytes, Laenge der Bytes) als Tupel 
# wichtig für encode-Me
def decode_variable_length(data):
    if not data:
        return None, 0
    
    first_byte = data[0]
    if first_byte & 0xC0 == 0:
        # 1 Byte, 6-Bit-Wert
        return first_byte, 1
    elif first_byte & 0xC0 == 0x40:
        # 2 Bytes, 14-Bit-Wert
        return struct.unpack('!H', data[:2])[0] & 0x3FFF, 2
    elif first_byte & 0xC0 == 0x80:
        # 3 Bytes, 22-Bit-Wert
        return struct.unpack('!I', b'\x00' + data[:3])[0] & 0x3FFFFF, 3
    else:
        # 4 Bytes, 30-Bit-Wert
        return struct.unpack('!I', data[:4])[0] & 0x3FFFFFFF, 4




## -------------------------------------------- BLTP-Packet --------------------------------------------


# BLTPPacket besteht aus base_header, extension_header und einer payload (wie nach RFC)
# verfuegt ueber die Funktionen wie encode() [konvertiert BLTPPacket zu Bytedarstellung], decode() [konvertiert Bytedarstellung in BLTPPacket] 

class BLTPPacket: 
    def __init__(self, base_header: BaseHeader, extension_header: None, payload: bytes = None):
        self.base_header = base_header
        self.extension_header = extension_header # can be more than one
        self.payload = payload if payload is not None else b''


    # Gibt die Leange der Payload eines BLTPPackets zurueck
    def length(self):
        #print(f"Payloadlength: {len(self.payload)}")
        return len(self.payload) if self.payload is not None else 0


    # Funktion, die ein BLTPPacket in Bytedarstellung konvertiert 
    def encode(self, shift=None): 
        data = b""


        #---------------- encode: base_header ----------------

        # fixed size auf seq_num und ack_num
        # seq_num und ack_num haben beide ein fixed_size von 32(-bits) somit wird encode_fixed_size auf 32 bit verwendet 
        data += encode_fixed_size(self.base_header.seq_num, 32)
        data += encode_fixed_size(self.base_header.ack_num, 32)


        # variable_length auf rcv_window und next_header
        # Alle drei haben keine fixed_size, sodass diese mittels variable_length encoded werden muessen
        data += encode_variable_length(self.base_header.rcv_window)
        data += encode_variable_length(self.base_header.next_header.value)


        #---------------- encode: extension_header ----------------

        # verarbeite den extension_header, wobei nur die Laenge mittel variable_length encoded wird    
        for i, extension_head in enumerate(self.extension_header):
            data += encode_variable_length(extension_head.length)


            #Falls specific_data existiert, so soll dieser auch encoded werden
            if extension_head.specific_data is not None:
                data += extension_head.specific_data


            # Bestimme, ob der next_header_value = 0, ansonsten muss noch der next_header_value encoded werden
            next_header_value = 0 if (i + 1) == len(self.extension_header) else self.extension_header[i + 1].next_header.value
            data += encode_variable_length(next_header_value)


        #---------------- encode: payload ----------------

        # check if extension headers contains ENCRYPTION
        # falls eine Payload vorhanden ist, so soll entweder mittels caesar_encryption die Payload encoded werden
        # oder die Payload wird normal encoded ohne encryption
        if self.payload is not None and self.payload != b"":
            if shift is not None:
                data += caesar_encrypt_bytes(self.payload.encode('utf-8'), shift)
            else:
                data += self.payload.encode('utf-8')    # encode the payload to utf-8
        
        return data
    

# Funktion decode ist eine Methode, die eine Bytedarstellung in ein BLTPPacket konvertiert 
def decode(data, shift=None) -> BLTPPacket:
    # current_pos gibt die aktuelle Position in unserer Bitfolge an 
    # wir benutzen current_pos um festzustellen an welcher Position der Bitfolge was decoded werden muss 
    # also ob aktuell seq_num oder nxt_header 
    # slice mit current_pos also unsere Bitfolge
    current_pos = 0

    if not data:
        return None
    
    #---------------- decode: base_header ----------------

    # erste 32 bits sind seq_num
    seq_num = decode_fixed_size(data[current_pos:current_pos + 4], 32)
    # inkrementiere current_pos um 4, da 32-bits = 4 Bytes
    current_pos += 4        
    
    # weiteren 32 bits sind ack_num
    # inkrementiere current_pos um 4, da 32-bits = 4 Bytes
    ack_num = decode_fixed_size(data[current_pos:current_pos + 4], 32)
    current_pos += 4

    # naechsten 2 bits are len of rcv_window
    # decode_variable_length(data) gibt Tupel von (data, length von data) 
    # inkrementiere als current_pos um die length von data
    rcv_window, length = decode_variable_length(data[current_pos:])
    current_pos += length

    # next 2 bits are len of nxt_header
    nxt_header, length = decode_variable_length(data[current_pos:])
    current_pos += length

    # erstelle base_header aus den dekodierten Daten 
    base_header = BaseHeader(seq_num, ack_num, rcv_window, HeaderType(nxt_header))

    
    #---------------- decode: extension_header ----------------
    
    # inkrementierung von current_pos geschieht hier analog zu oben
     
    extension_header = []
    while nxt_header != HeaderType.NO_HEADER.value:
        if current_pos >= len(data):
            break

        # next 2 bits are len of extention_header
        extension_header_len, length = decode_variable_length(data[current_pos:])
        current_pos += length

        if current_pos + extension_header_len > len(data):
            break

        # next extention_header_len bits are extention_header_data
        extention_header_data = data[current_pos:current_pos + extension_header_len]
        current_pos += extension_header_len

        # next 2 bits are len of nxt_header
        extension_header.append(ExtensionHeader(extension_header_len, HeaderType(nxt_header), extention_header_data))
        #print(f"decode: ExtensionHeader: {extension_header[0].next_header}")
        nxt_header, length = decode_variable_length(data[current_pos:])
        logging.debug(f"decode: HeaderType: {nxt_header}")
        logging.debug(f"decode: HeaderType: {HeaderType(nxt_header)}")
        if nxt_header is None:
            logging.debug(f"decode: HeaderType: {nxt_header},{HeaderType(nxt_header)}")
            logging.debug("Failed to decode next_header.")
            return None
        current_pos += length

        

        if nxt_header == HeaderType.NO_HEADER.value:
            break


    #---------------- decode: payload ----------------

    # Falls current_pos < len(data) ist, dann existiert logischerweise keine payload
    if current_pos < len(data):
        # ueberpruefe ob encryption angewandt werden muss 
        if shift is not None:
            payload_data = caesar_decrypt_bytes(data[current_pos:], shift)
        else:
            payload_data = data[current_pos:]
    else:
        payload_data = None

    return BLTPPacket(base_header, extension_header, payload_data)


# ------------------------------------- Kapitel X: Caeser Encryption -------------------------------------

# Verschlüsselung der Nachricht
def caesar_encrypt_bytes(plaintext_bytes, shift):
    encrypted_bytes = bytearray()
    for byte in plaintext_bytes:
        encrypted_byte = (byte + shift) % 256
        encrypted_bytes.append(encrypted_byte)
    return bytes(encrypted_bytes)

def caesar_decrypt_bytes(encrypted_bytes, shift):
    decrypted_bytes = bytearray()
    for byte in encrypted_bytes:
        decrypted_byte = (byte - shift) % 256
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

# ------------------------------------- Kapitel 3: Connections ------------------------------------- 

# Die Klasse BLTPConnection beinhaltet alle Funktionalitaeten fuer die Kommunikation mit BLTP als Protokoll 
# Es beinhaltet Funktionen, wie send(), recv(), Logik fuer retransmission und congestion_control
# den receive_handler, der alle einkommenden Daten verarbeitet. z.B den Handshake, Payload auslesen und Verbindung schließen   


#definiere States aus dem Automaten (aus dem RFC entnommen)       
class State(Enum):
    CLIENT_INIT = 0
    SERVER_INIT = 1
    HALF_OPEN = 2
    ESTABLISHED = 3
    CLOSE_WAIT = 4
    HALF_CLOSED = 5
    EOF = 6
    EOF_WAIT = 7
    CLOSED = 8
    LISTEN = 9  # nach Figure 2 BLTP peer B



class BLTPConnection:
    def __init__(self, address, port, peer_address, peer_port, sock):
        self.address = address
        self.port = port
        #self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.state = State.CLOSED
        self.seq_num = 0
        self.ack_num = 0
        self.rcv_window = 1024
        self.peer_window_size = 10  #gibt das Intervall an, in dem der Empfänger Daten empfangen kann 
        self.shift = None
        self.peer_address = peer_address
        self.peer_port = peer_port

        # Buffer fuer Packete uns Retramission
        self.sent_packets = {}      # speichert die gesendeten Packete mit einem 2-Tupel (packet, time_send), welche über die seq_num als Index erreichbar sind 
        self.retransmit_queue = deque() # speichert die gesendeten Packete und deren seq_num, um die retransmit_time zu berechnen und um auf die Paket in sent_packets zuzugreifen 
        #self.lock = threading.Lock()       # Mutex 

        # Timer fuer Retransmission
        self.retransmit_interval = 2 # Sekunden
        self.retransmit_timer = None

        # delayed ack Attribute
        self.ack_packets = {}       
        self.ack_queue = deque()
        self.delayed_ack_intervall = 0.2    #intervall in dem ein delayed_ack spätestens gesendet werden muss 

        # congestion-window Attribute
        self.congestion_window = 10     # Initialwert vom congestion-window 
        self.congestion_packets = set()   # speichert die akutellen Pakete die gesendet wurden, aber nicht bestätigt wurden
        self.acked_packet_num = 0             # die Anzahl der aktuell bestätigten Packet durch ACKs


        self.received_data = b""    # Buffer für empfangene Nachrichten

        self.sock = sock    


    # Funktion sendet daten, die vorerst aber encoded (also in Bytedarstellung konvertiert) werden müssen 
    # Falls das Packet die rcv_window size übertrifft, wird das Packet gesliced und das Packet mit der kleineren seq-num als ersten versendet
    def send(self, packet: BLTPPacket, retransmit = False):

        # Falls das congestion window ueberschritten wurde so soll das Paket verworfen werden
        if len(self.congestion_packets) >= self.congestion_window:
            logging.debug(f"Congestion window exceeded...")
            time.sleep(2)
            return


        # check if packet is too large
        # if so, slice it
        # and send the rest of the packet

        sliced_packet = None # wird noch nicht gesendet, falls das zu sendende Paket zu groß ist(2. Teil der Payload)
        if self.seq_num + packet.length() > self.peer_window_size:
            sliced_base_header = BaseHeader(packet.base_header.seq_num + len(packet.payload[:self.peer_window_size]), packet.base_header.ack_num, packet.base_header.rcv_window, packet.base_header.next_header)
            sliced_packet = BLTPPacket(sliced_base_header, packet.extension_header, packet.payload[self.peer_window_size:])
            
            # erstelle das erste Packet
            # slice durch die peer_window_size
            packet.payload = packet.payload[:self.peer_window_size]

        data_encoded = packet.encode(self.shift)
        logging.debug(f"Sending data: {data_encoded}")
        #logging.debug(f"Sending to address: {self.peer_address}, port: {self.peer_port}")
        
        
        # send the packet oder den ersten Teil des Packets
        try:
            #self.socket.seƒndto(data_encoded, (self.peer_address, self.peer_port))
            print(f"encodede data: {data_encoded}")

            self.sock.send(data_encoded, self.peer_address, self.peer_port)

            logging.debug("Data sent successfully.")

            #fuege Packet zur Liste der gesendeten Packet im aktuellen congestion_window hinzu
            if not retransmit and self.state == State.ESTABLISHED and packet.base_header.next_header != HeaderType.FIN_RST:
                self.congestion_packets.add(packet) 

                # fuege Packete und deren seq_num in den Buffer ein 
                cur_time = time.time()
                self.sent_packets[packet.base_header.seq_num] = (packet, cur_time)
                self.retransmit_queue.append(packet.base_header.seq_num)
            #self.packet_num += 1    #inkrementiere die packet-num 

                self.retransmit_timer = self.start_retransmit_timer()

            # sequenznummer anpassen (nach TCP-Logik)
            if not retransmit:
                self.seq_num += packet.length()

        except Exception as e:
            logging.error(f"Failed to send data: {e}")
            return 0
        
        # send rest of the packet
        # wait 2 s oder so
        if sliced_packet is not None: 
            time.sleep(2)
            self.send(sliced_packet)    # rufe send(BLTPPacket) rekursiv auf das ggf. verbleibende Packet auf
        
        return len(packet.payload)


    # benutze die Funktion, um Daten bzw eine Payload zu senden 
    # Die seq_num soll ich um die Laenge der Payload erhoehen
    def send_message(self, data:BLTPPacket):
        payload_length = data.length()
        
        # erhoehe die seq_num um die Laenge der Bytes 
        self.seq_num = self.seq_num + payload_length  
        payload_baseheader = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.NO_HEADER)
        payload_paket = BLTPPacket(payload_baseheader, [], None)
        self.send(payload_paket)

#-------------------------------------- Retransmit --------------------------------------

    

    # Funktion, die den Retransmit-timer startet - muss manuell, wiederholt, aufgerufen werden
    def start_retransmit_timer(self):
        #self.retransmit_timer.cancel()
        if self.sock is None or self.state == State.CLOSED:
            if self.retransmit_timer is not None:
                self.retransmit_timer.cancel()
            return
        
        if self.sock is not None:
            self.sock.timeout(self.retransmit_interval)
            self.listen_for_ack()
            self.sock.timeout(None)

        self.retransmit_timer = threading.Timer(self.retransmit_interval, self.retransmit_packets)
        self.retransmit_timer.start()
        #self.retransmit_timer.cancel()
        #self.retransmit_timer = None

    # Schickt Pakete neu, falls kein Ack für eine seq-num im Intervall empfangen wurde 
    def retransmit_packets(self):
        current_time = time.time()

        # check for acks

        # geht die Liste der retransmit_queue durch und ueberprueft, ob das packet zeitlich ueber dem vordefinierten Intervall liegt 
        # falls es der Fall ist, so soll das Paket retransmitted werden 
        for seq_num in list(self.retransmit_queue):
            packet, sent_time = self.sent_packets.get(seq_num, (None, None))    #sucht nach einen Eintrag mit seq_num, falls dieser nicht existiert wird (None. None) zurueckgegeben
            # Wenn das Intervall ueberschritten wurde, dann wird das Paket retransmitted 
            if packet and (current_time - sent_time > self.retransmit_interval):
                self.send(packet, retransmit = True)       # retransmitte das Paket
                cur_time = time.time()
                self.sent_packets[seq_num] = (packet, cur_time)
                self.congestion_window = round(self.congestion_window / 2)      # halbiere Window, falls ein Packet retransmitted werden muss 
        self.start_retransmit_timer()


    # loescht die Eintraege von Paketen mit seq_num = ack_num  aus de rretransmission queue und congestion_queue
    # also falls ein ACK empfangen wurde so soll die Sequenznummer aus der send_packets List entfernt werden, damit das Packet nicht nochmal retransmited wird
    def ack_received(self, paket_ack_num: BLTPPacket): 
        self.last_ack_num = paket_ack_num.base_header.ack_num if paket_ack_num.base_header.ack_num > self.last_ack_num else self.last_ack_num

        ack_num = paket_ack_num.base_header.ack_num

        for seq_num in list(self.retransmit_queue):
            if seq_num <= self.last_ack_num:
                self.retransmit_queue.remove(seq_num)

                if seq_num in self.sent_packets:
                    del self.sent_packets[seq_num]

        for packe in list(self.congestion_packets):
            if packe.base_header.ack_num <= self.last_ack_num:
                self.congestion_packets.remove(packe)
                self.acked_packet_num += 1

        # ueberpruefe, ob das erhaltene ACK in unserer Liste der gesendeten Pakte ist
        if ack_num in self.sent_packets: 
            del self.sent_packets[ack_num]
            self.retransmit_queue.remove(ack_num)
            #logging.debug(f"ACK received for seq_num: {ack_num}")

        # pruefe, ob ack_num in set von den seq_nums in der congestion_queue ist 
        # Falls ja, entferne auch das aus der Liste 
        if ack_num in self.congestion_packets: 
            self.congestion_packets.remove(ack_num)
            self.acked_packet_num += 1
        
        # pruefe, ob alle Packet im congestion_window bestaetigt wurden
        # falls ja inkrementiere die congestion_window_size um 1 (nach RFC)
        if self.acked_packet_num >= self.congestion_window:
            self.congestion_window += 1
            self.acked_packet_num = 0



    ## sendet asuf jedes empfangende Packet ein Ack zurück
    # benutze nicht self.send(BLTPPacket), da Acks nicht in die Retransmission queue gepackt werden sollen
    # benutze stattdessen die socket.send() Funktion, damit ACK-Pakete nicht gequeued werden 
    def send_ACK(self, ack_num):
        print(f"Sending ACK for seq_num: {ack_num}")
        base_ack_packet = BaseHeader(self.seq_num, ack_num, self.rcv_window, HeaderType.NO_HEADER)
        ack_packet = BLTPPacket(base_ack_packet, [], None)
        self.sock.send(ack_packet.encode(), self.peer_address, self.peer_port)
        #self.socket.sendto(ack_packet.encode(), (self.peer_address, self.peer_port))   
        logging.debug(f"ACK sent: {ack_packet.encode()}")


    # Funktion recv() empfaengt encoded Daten und gibt die Daten Dekodiert zurueck 
    # Gibt Tupel von (BLTPPacket, address)
    def recv(self) -> BLTPPacket:
        if self.state == State.CLOSED:
            return None
        try:
           
           data = self.sock.receive((self.peer_address, self.peer_port))
           if data is None:
                return None

           logging.debug(f"Data received: {data}\n") 
           data_decoded = decode(data, self.shift)
           # aktualisiere peer_window size nach empfangen von Daten
           self.peer_window_size = data_decoded.base_header.ack_num + data_decoded.base_header.rcv_window
           self.last_ack_num = data_decoded.base_header.ack_num
           #self.send_ACK(data_decoded.base_header.seq_num)
           return data_decoded
        
        except Exception as e:
            logging.error(f"Failed to receive data: {e}")
            return None
    
    def recv_message(self):
        packet = self.recv()
        return packet.payload
    

    # Funktion die den State aktualisiert, woebei new_state := als der neue State 
    def update_state(self, new_state):
        self.state = new_state
        logging.debug(f"State updated to: {self.state}\n")


    def recv_temp(self):
        try:
           data = self.sock.receive_temp((self.peer_address, self.peer_port))

           ## data is list of packets
           if data is None:
                return None
           
           data_decoded = [decode(packet, self.shift) for packet in data]
           return data_decoded
        except Exception as e:
            return None
        


    def listen_for_fin(self):
        packets = self.recv_temp()

        if packets is [] or packets is None:
            return
        
        for packet in packets:
            if HeaderType.FIN_RST in [header.next_header for header in packet.extension_header] or HeaderType.FIN_RST == packet.base_header.next_header:
                self.peer_window_size = packet.base_header.ack_num + packet.base_header.rcv_window
                self.last_ack_num = packet.base_header.ack_num
                self.FIN_process(packet)
                return
    
    def listen_for_ack(self):
        packets = self.recv_temp()


        if packets is [] or packets is None:
            return
        
        for packet in packets:
            if packet.extension_header == [] and (packet.payload == b'' or packet.payload is None):
                #self.peer_window_size = packet.base_header.ack_num + packet.base_header.rcv_window
                #self.last_ack_num = packet.base_header.ack_num
                self.ack_received(packet)
                return

    # Funktion die alle einkommenden Nachrichten handled und der Kern für Verbindungsauf- und -abbau ist
    # Diese Funktion handled den Handshake, das Empfangen und Senden von Daten und alle von uns definierten HEADERTYPES   
    def receive_handler(self):

        packet = self.recv()

        if packet is None:
            return
        
        #print(f"ack num: {packet.base_header.ack_num}")

        self.ack_received(packet)
        
        

        #Fuer den Fall, dass in einem Paket mehrere Flags gesetzt sind 
        handshake_proc = False
        data_proc = False
        fin_proc = False

        counter = 0

        ## quote RFC 478, 3.3: The order of processing MUST be, first Handshake-Header, then Data, then FIN-Header.

        #-------------------------------- HEADERTYPE-handling -------------------------------- 
        # Dieser Abschnitt befasst sich mit dem Handling von den definierten Headertypes bzw Headerflags wie z.B: HANDSHAKE, NO_HEADER, FIN_RST
        # 


        #---------------- HEADERTYPE: HANDSHAKE ----------------

        # Handshake-Flag ist gesetzt
        # Client oder server will Handshake durchführen 
        # rufe unseren handshake-handler: handshake(data) auf  
        if HeaderType.HANDSHAKE in [header.next_header for header in packet.extension_header] or HeaderType.HANDSHAKE == packet.base_header.next_header:
            self.handshake(packet)
            #handshake_processed = True

        #---------------- HEADERTYPE: FIN_RST ----------------

        # FIN/RST-Flag is gesetzt
        if HeaderType.FIN_RST in [header.next_header for header in packet.extension_header] or HeaderType.FIN_RST == packet.base_header.next_header:
            #print(f"FIN/RST-Flag is set (!)")

            """self.FIN_process(packet)
            return"""
            n = True if packet.base_header.next_header == HeaderType.FIN_RST else False
            for header in packet.extension_header:

                if n:
                    header = FinRstHeader(header.length, header.next_header, header.specific_data)
                    if header.is_rst():
                        self.RST_process(packet)
                        self.close_connection(False, header.error_code)
                    else:
                        self.FIN_process(packet)
                    return

                if header.next_header == HeaderType.FIN_RST:
                    n = True

                #print(f"header: {header.next_header}")

            return


        if self.state == State.SERVER_INIT:
            if packet.base_header.ack_num == 1 and packet.base_header.seq_num == 1:
                self.ack_num = packet.base_header.seq_num + 1

                self.update_state(State.ESTABLISHED)
                return

        # Zustaende, in denen RSTs gesendet werden sollen
        # Fall 1: Verbindung existiert nicht, Antwort auf alle eingehenden Nachrichten ist ein RST, ausser diese ist selbst ein RST
        # prueft ob der Header ein RST ist
        if self.state == State.CLOSED:
            rst = False
            if HeaderType.FIN_RST in [header.next_header for header in packet.extension_header] or HeaderType.FIN_RST == packet.base_header.next_header:
                for header in packet.extension_header:
                    if isinstance(header, FinRstHeader):
                        if header.is_rst():
                            rst = True
            

            # ist das erhaltene Paket kein RST wird ein RST gesendet
            if rst == False:
                base_header_RST = BaseHeader(packet.base_header.ack_num, packet.base_header.seq_num, 60, HeaderType.FIN_RST) 
                rst_header = FinRstHeader(1, HeaderType.NO_HEADER, 1) # Laenge muss angepasst werden -----------------------
                rst_packet = BLTPPacket(base_header_RST, [rst_header], None)
                self.send(rst_packet)
        
        # Fall 2: Verbindung ist unsynchronisiert und Pakete, die ein ungültiges ACK enthalten loesen ein RST aus
        if self.state == State.CLIENT_INIT or self.state == State.SERVER_INIT:
            if not (packet.base_header.ack_num in self.retransmit_queue):
                base_header_RST = BaseHeader(packet.base_header.ack_num, (packet.base_header.seq_num + 1), 60, HeaderType.FIN_RST)
                rst_header = FinRstHeader(1, HeaderType.NO_HEADER, 2) # Laenge muss angepasst werden -----------------------
                rst_packet = BLTPPacket(base_header_RST, [rst_header], None)
                self.send(rst_packet)
        
        # Fall 3: Verbindung ist synchronisiert; fehlerhafte SEQs und ACKs loesen keine RSTs sondern ein leeres Paket aus
        if self.state == State.ESTABLISHED or self.state == State.EOF or self.state == State.EOF_WAIT or self.state == State.CLOSE_WAIT or self.state == State.HALF_CLOSED:
                    if (packet.base_header.seq_num - self.ack_num) > self.rcv_window:
                        base_header = BaseHeader(self.seq_num, self.ack_num, 60, HeaderType.NO_HEADER)
                        empty_packet = BLTPPacket(base_header, [], None)
                        self.send(empty_packet)




        #---------------- HEADERTYPE: NO_HEADER ---------------- 

        # Keine weiteren Daten bzw Payload dürfen weiter gesendet werden, bevor der state nicht ESTABLiSHED ist 
        if HeaderType.NO_HEADER in [header.next_header for header in packet.extension_header] or HeaderType.NO_HEADER == packet.base_header.next_header:
            if self.state == State.ESTABLISHED:
                self.ack_received(packet)
            if self.state == State.ESTABLISHED and packet.payload is not None and packet.payload != b"":
                self.data_processing(packet)
                #data_processed = True
            elif self.state == State.SERVER_INIT:   # Fuer den Handshake auf der Server-Seite
                logging.debug(f"no-header Handshake von Funktion")
                #self.handshake(packet)
            elif self.state == State.HALF_CLOSED:
                logging.debug(f"no-header FIN_RST von Funktion")
                self.data_processing(packet)
            elif self.state == State.CLOSE_WAIT:
                logging.debug(f"no-header FIN_RST von Funktion")
                self.FIN_process(packet)
            elif self.state == State.EOF_WAIT:
                logging.debug(f"no-header FIN_RST von Funktion")
                self.FIN_process(packet)

        ## ENCRIPTION
        if HeaderType.ENCRYPTION in [header.next_header for header in packet.extension_header] or HeaderType.ENCRYPTION == packet.base_header.next_header:
            self.shift = int.from_bytes(packet.extension_header[0].specific_data)
            self.ack_num = packet.base_header.seq_num + 1
            print(f"Encryption enabled with shift: {self.shift}")


    # CASE: Headertype = HANDSHAKE    
    # Funktion, die den Hanshake handled, wenn Hanshake-flag gesetzt ist    
    # dabei wird zwischen Client-Seite und Server-Seite unterschieden
    # beide benutzen die gleiche Funktion für den Handshake indem zwischen den unterschiedlichen States unterschieden wird
    # die Unterscheidung wird nochmal deutlich die Markierung gemacht fuer welche Seite die Funktion bzw das handling gedacht ist 
    def handshake(self, packet: BLTPPacket):

        #-------------------------------------------- Client-Seite --------------------------------------------
    
        # Client in im State : CLIENT_INIT 
        # d.h der CLIENT hat den Handshake schon initialisiert 
        if self.state == State.CLIENT_INIT:
            logging.debug(f"in receive-Handler State: CLIENT_INIT")
            logging.debug(f"data: {packet}")
            logging.debug(f"data2: {packet.encode(self.shift)}")
            logging.debug(f"Packet next_header: {packet.base_header.next_header}")
            if HeaderType.HANDSHAKE in [header.next_header for header in packet.extension_header] or HeaderType.HANDSHAKE == packet.base_header.next_header:
                if packet.base_header.ack_num == 1:     #erwartet eine Antwort auf den gesendeten Handshake
                    logging.debug(f"1Handshake mit gesetzter SYN flag wurde empfangen\n")
                    self.update_state(State.ESTABLISHED)
                    # State ist nun ESTABLISHED

                    # passe Attribute wie seq_num und ack_num and und sende ein ACK auf den Handshake 
                    self.seq_num = packet.base_header.ack_num
                    self.ack_num = packet.base_header.seq_num + 1
                    base_header = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.NO_HEADER)
                    bltp_packet = BLTPPacket(base_header, [], None)
                    
                    #self.send(bltp_packet)  # sende das packet mit den baseheader 
                    self.send_ACK(packet.base_header.ack_num)

                    return
            

        #-------------------------------------------- Server-Seite --------------------------------------------    

        # zunaechst ist der State des Servers in LISTEN 
        # d.h der Server wartet auf ein einkommendess Handshake-paket  
        if self.state == State.LISTEN:

            logging.debug(f"in receive-Handler State: LISTEN")
            logging.debug(f"data: {packet}")
            logging.debug(f"data2: {packet.encode(self.shift)}")
            logging.debug(f"Packet next_header: {packet.base_header.next_header}")

            if HeaderType.HANDSHAKE in [header.next_header for header in packet.extension_header] or HeaderType.HANDSHAKE == packet.base_header.next_header:
                
                # Handshake-paket soll immer mit seq_num = 0 und ack_num = 0 anfangen 
                if packet.base_header.seq_num == 0 and packet.base_header.ack_num == 0:  
                    
                    logging.debug(f"1Handshake mit gesetzter SYN flag wurde empfangen\n")
                    self.update_state(State.SERVER_INIT)


                    # sende ein Paket mit gesetzter SYN-Flag (HANDSHAKE-flag) zurueck 
                    # Logik des three-way-handshakes
                    self.seq_num = packet.base_header.ack_num
                    self.ack_num = packet.base_header.seq_num + 1
                    base_header = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.HANDSHAKE)
                    bltp_packet = BLTPPacket(base_header, [HandshakeHeader(0, HeaderType.NO_HEADER, 1140)], None)

                    self.send(bltp_packet)
                    
                    self.seq_num += 1

                    packet = self.recv()  #warte auf Ack-packet#### hier

                    if packet.base_header.ack_num == 1 and packet.base_header.seq_num == 1:
                        self.ack_num = packet.base_header.seq_num + 1
                        self.update_state(State.ESTABLISHED)
                return
            

    # -------------------------------------------- Client und Server --------------------------------------------
    
    # CASE: Receiving FIN 
    # Funktion, die den connection closing handlet, wenn FIN-flag gestzt ist 
    def FIN_process(self, packet: BLTPPacket):
        
        # ein FIN kann nur verarbeitet werden, wenn der STATE = State.ESTABLISHED ist 
        print("-----FIN PROC------")
        print(f"State: {self.state}")
        print(f"Packet seq_num (from other peer): {packet.base_header.seq_num}")
        print(f"Packet ack_num: {packet.base_header.ack_num}")
        print(f"-------------------")

        if self.state == State.ESTABLISHED: ## server
            logging.debug(f"In FIN_process")
            if HeaderType.FIN_RST in [header.next_header for header in packet.extension_header] or HeaderType.FIN_RST == packet.base_header.next_header:
                logging.debug(f"FIN flag wurde empfangen\n")
                logging.debug(f"FIN packet: {packet}")
                self.ack_num = packet.base_header.seq_num + 1
                self.update_state(State.EOF)

                #sende ein ACK auf das empfangende FIN
                base_header = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.NO_HEADER)
                bltp_packet = BLTPPacket(base_header, [], None)
                    
                self.send(bltp_packet)

                # Verbindung wird geschlossen: Erst oben ACK senden und dann das FIN Paket senden, könnte man auch zusammenfassen :)
                base_header_FIN = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.FIN_RST)
                fin_packet = BLTPPacket(base_header_FIN, [FinRstHeader(0, HeaderType.NO_HEADER, None, None)], None)
                self.send(fin_packet)
                self.seq_num += 1

                self.update_state(State.EOF_WAIT)
                self.receive_handler()

            return


        # State: CLOSE_WAIT 
        # wechsle in HALF_CLOSED wenn erwartes ACK empfangen wurde
        if self.state == State.CLOSE_WAIT:

            logging.debug(f"CLOSE_WAIT Funktion")
            logging.debug(f"seq_num: {self.seq_num} and ack_num: {packet.base_header.ack_num}")

            if (HeaderType.FIN_RST in [header.next_header for header in packet.extension_header] + [packet.base_header.next_header]) and self.seq_num == packet.base_header.ack_num:
                self.ack_num = packet.base_header.seq_num + 1

                base_header = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.NO_HEADER)
                bltp_packet = BLTPPacket(base_header, [], None)

                self.send(bltp_packet)

                self.update_state(State.CLOSED)
                self.close_connection(normal = True)
                return
            if HeaderType.FIN_RST in [header.next_header for header in packet.extension_header] + [packet.base_header.next_header]:
                self.ack_num = packet.base_header.seq_num + 1
                base_header = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.NO_HEADER)
                bltp_packet = BLTPPacket(base_header, [], None)

                self.send(bltp_packet)
                self.update_state(State.EOF_WAIT)
                self.receive_handler()
                return
            if self.seq_num + 1 == packet.base_header.ack_num:
                self.ack_num = packet.base_header.seq_num 
                self.update_state(State.HALF_CLOSED)
                self.receive_handler()
                return

            self.receive_handler()
            return

        # State: HALF_CLOSED
        # sende ein letztes ACK auf und wechsle dann in den STATE: CLOSED
        if self.state == State.HALF_CLOSED:
            if HeaderType.FIN_RST in [header.next_header for header in packet.extension_header] + [packet.base_header.next_header]:
                
                self.ack_num = packet.base_header.seq_num + 1

                base_header = BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.NO_HEADER)
                bltp_packet = BLTPPacket(base_header, [], None)

                self.send(bltp_packet)
                self.close_connection(normal = True)    #connection closing wurde normal durchgeführt mit FIN-Handshake
                self.update_state(State.CLOSED)

            return
        
        # Schließe die komplette Connection 
        if self.state == State.EOF_WAIT:
            if self.seq_num == packet.base_header.ack_num:
                self.close_connection(normal = True)
            if self.seq_num + 1 == packet.base_header.ack_num:
                # Wir kiiennen davon ausgehen, dass die Verbindung normal getrennt wurde
                # da der STAT: EOF_WAIT erreicht wurde - setze also normal = True 
                self.close_connection(normal = True)        
                self.update_state(State.CLOSED)
                return
            self.receive_handler()
            return
        return
    

    def RST_process(self, packet: BLTPPacket):
        
        if self.state == State.CLIENT_INIT:
            if self.seq_num + 1 == packet.base_header.ack_num:
                self.close_connection(False) # schliesst socket und gibt fehlermeldung aus
                self.update_state(State.CLOSED)
            return
        else:
            if packet.base_header.seq_num <= self.rcv_window and not (self.state == State.LISTEN or self.state is None):
                self.close_connection(False)
                self.update_state(State.CLOSED)
            return
                

    ## -------------------------------------------- Data receiving --------------------------------------------


    # Diese Funktion soll Daten, die eine Payload haben verarbeiten 
    # Daten koennen nur verarbeitet werdem. wenn der STATE: ESTABLISHED ist 
    # sende daraufhin ein ACK mit der richtigen ack_num weil das Paket erfolgrreich empfangen wurde 
    def data_processing(self, packet: BLTPPacket): 
        payload = packet.payload
        logging.debug(f"Payload: {payload}")

        self.received_data += payload

        self.ack_num = packet.base_header.seq_num + packet.length()
        ## sende ggf. Nachricht, was für Daten empfangen wurden
        self.send_ACK(self.ack_num)     # send ack for the received packet


    ## -------------------------------------------- Closing-connection handler --------------------------------------------


    ## Funktion, die die Art des Closing zurueckgibt

    def close_connection(self, normal, err_code = None):
        
        # Falls normal = True, dann geht man von einem Verbindungsabbau mittels FIN aus, der ohne Komplikationen verlaufen ist 
        if normal:
            logging.debug(f"Connection closed normally!")
        else:
            # Falls normal != True, dann wird von einem irregulären Verbindungsabbau ausgegangen 
            logging.debug(f"Connection aborted!")
            if err_code is not None: 
                msg = ""
                if err_code == 0:
                    msg = "ordinary shutdown"
                elif err_code == 1:
                    msg = "unknown reason"
                elif err_code == 2: 
                    msg = "invalid received packet"
                elif err_code == 0:
                    msg = "not wanted estbablishement"
                logging.debug(err_code)
                logging.error(msg)
        self.update_state(State.CLOSED)
        #self.sock.close() 
        #self.socket.close()
        #self.inform_application(normal)


    def inform_application(self, normal):
        if normal:
            print("Connection closed normally.")
        else:
            print("Connection was aborted.")

    def enable_encryption(self):
        if self.shift is not None:
            return
        self.shift = random.randint(1, 255) 
        send_packet = BLTPPacket(BaseHeader(self.seq_num, self.ack_num, self.rcv_window, HeaderType.ENCRYPTION), [ExtensionHeader(1, HeaderType.NO_HEADER, self.shift.to_bytes())], None)
        self.send(send_packet)


# ------------------------------------- Kapitel 4: Data Communication ------------------------------------- 


