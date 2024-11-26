import logging
import socket
import sys
from clientInit import BLTPClient
from serverInit import BLTPServer
import sock
import time
from bltp import BLTPConnection, State, BaseHeader, BLTPPacket, HeaderType, encode_variable_length, decode_variable_length, FinRstHeader


logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # change to ERROR for production

connections = {}
possible_cons = {}
accepted_cons = []
socke = None
i = 0

def start():
    global socke
    global i
    if socke is not None: # check for new connection
        if not(accepted_cons == [] and possible_cons == {} and connections == {}):
            socke.timeout(2)
        socke.receive(('0.0.0.0', -1))
        socke.timeout(None)

        

        if socke.server:
            for pos_new_con in socke.messages_received.keys():
                if not(pos_new_con in possible_cons.values() or pos_new_con in accepted_cons):
                    possible_cons[i] = pos_new_con
                    print(f"possible connection: local: {i} address:{pos_new_con}")
                    i += 1
            ## check for fin packet...
            for con in connections.values():
                con.connection.listen_for_fin()
    
    

def connect(remote_ip, remote_port):
    global socke
    global i

    socke = sock.BLTPSocket('127.0.0.1', 12345, False)
    client = BLTPClient('127.0.0.1', 12345, remote_ip, remote_port, socke)
    connections[i] = client
    print(f"Connectionidentifier: {i}")
    i += 1
    client.start()

    connections[i-1].connection.receive_handler()

def listen(local_ip, local_port):
    global socke
    global i

    socke = sock.BLTPSocket(local_ip, local_port, True)

def accept(con):
    global socke
    global i

    server = BLTPServer(socke.address, socke.port, possible_cons[con][0], possible_cons[con][1], socke)
    connections[con] = server

    accepted_cons.append(possible_cons[con])
    
    del possible_cons[con]
    server.start()
    print(f"Connection {con} accepted")

    connections[con].connection.receive_handler()

def send(con, msg):
    global socke
    global i 

    try:
        sent_data = connections[con].connection.send(BLTPPacket(BaseHeader(connections[con].connection.seq_num, connections[con].connection.ack_num, 60, HeaderType.NO_HEADER), [], bytes(msg, 'utf-8')))
        logging.debug(f"Dataamount sent: {sent_data}")
    except KeyError as kerror:
        logging.error("An error occured while sending the message")
        ui()
        return
    

def receive(con, byte_count, timeout, max_time):
    global socke
    global i
    
    while len(connections[con].connection.received_data) < byte_count and (timeout == -1 or time.time() < max_time):
        connections[con].connection.receive_handler()

    received = connections[con].connection.received_data[:byte_count]
    connections[con].connection.received_data = connections[con].connection.received_data[byte_count:]
    return received

def close(con):
    global socke
    global i

    base_header_FIN = BaseHeader(1, 1, 60, HeaderType.FIN_RST)
    fin_packet = BLTPPacket(base_header_FIN, [FinRstHeader(0, HeaderType.NO_HEADER, None, None)], None)
    connections[con].connection.send(fin_packet)
    connections[con].connection.update_state(State.CLOSE_WAIT)
    logging.debug(f"FIN packet sent\n")
    while connections[con].connection.state != State.CLOSED:
        connections[con].connection.receive_handler()
    del connections[con]

    socke = None

def ui():
    global socke
    global i

    start()

    for con in connections:
        if connections[con].connection.state == State.CLOSED:
            print(f"Connection {con} closed")
            
            accepted_cons.pop(accepted_cons.index((connections[con].peer_address, connections[con].peer_port)))
            del connections[con]
            ui()
            return
                        
    cmd = input("")

    if cmd.startswith("CONNECT"):
        try:
            remote_ip, remote_port = cmd.split(" ")[1], int(cmd.split(" ")[2])
        except IndexError:
            logging.error("wrong format: CONNECT (remote IP address, remote port)")
            ui()
            return
        except ValueError:
            logging.error("wrong format: CONNECT (remote IP address, remote port)")
            ui()
            return
        ## verify if ip is valid from https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
        try:
            socket.inet_aton(remote_ip)
            # legal
        except socket.error:
            logging.error("IP address is not correct.")
            ui()
            return

        if (remote_port) < 1024 or (remote_port) > 65535:
            logging.error("Port is not valid")
            ui()
            return
        
        connect(remote_ip, remote_port)
        ui()
        return
    
    if cmd.startswith("LISTEN"):
        local_ip = '127.0.0.1'
        try:
            local_port = int(cmd.split(" ")[1]) # TODO options?????
        except IndexError:
            logging.error("wrong format: LISTEN (local port [, local IP address] [, options])")
            ui()
            return
        except ValueError:
            logging.error("wrong format: LISTEN (local port [, local IP address] [, options])")
            ui()
            return
        ## verify if port is valid
        if (local_port) < 1024 or (local_port) > 65535:
            logging.error("Port is not valid")
            ui()
            return
        
        listen(local_ip, local_port)

        ui()
        return
    
    if cmd.startswith("ACCEPT"): ## more than one connection TODO ??? not todo right? od och...
        try:
            con = int(cmd.split(" ")[1])
        except IndexError:
            logging.error("wrong format: ACCEPT (local socket name)")
            ui()
            return
        except ValueError:
            logging.error("wrong format: ACCEPT (local socket name)")
            ui()
            return
        
        if possible_cons.get(con) == None:
            logging.error("Connection not possible")
            ui()
            return
        
        accept(con)



        ui()
        return

    
    if cmd.startswith("SEND"):
        try:
            con = int(cmd.split(" ")[1])
            msg = cmd.split(" ")[2]
        except ValueError as verror:
            logging.error("wrong format: SEND(local connection name, data [, timeout]) ")
            ui()
            return
        except IndexError as Inderror:
            logging.error("wrong format: SEND(local connection name, data [, timeout]) ")
            ui()
            return
        
        if len(cmd.split(" ")) == 4:
            timeout = int(cmd.split(" ")[3])
            if timeout < 0:
                logging.error("timeout must be a positive integer")
                ui()
                return
            socke.timeout(timeout)

        send(con, msg)

    
        ui()
        return
    
    if cmd.startswith("RECEIVE"):
        timeout = -1
        try:
            con = int(cmd.split(" ")[1])
            byte_count = int(cmd.split(" ")[2])
        except ValueError as verror:
            logging.error("wrong format: RECEIVE(local connection name, byte count, [timeout])")
            ui()
            return
        except IndexError as Inderror:
            logging.error("wrong format: RECEIVE(local connection name, byte count, [timeout])")
            ui()
            return 
        
        max_time = time.time()
        if len(cmd.split(" ")) == 4:
            timeout = int(cmd.split(" ")[3])
            if timeout < 0:
                logging.error("timeout must be a positive integer")
                ui()
                return
            socke.timeout(timeout)
            max_time += timeout


        received = receive(con, byte_count, timeout, max_time)

        print(f"Received: {received}")
        ui()
        return
    
    ## only can sent by client
    if cmd.startswith("CLOSE"):
        if socke.server:
            logging.error("Server can't close connection")
            ui()
            return

        try:
            con = int(cmd.split(" ")[1])
        except ValueError as verror:
            logging.error("wrong format: CLOSE(local connection name)")
            ui()
            return
        except IndexError as Inderror:
            logging.error("wrong format: CLOSE(local connection name)")
            ui()
            return
        if connections.get(con) == None:
            logging.error("Connection does not exist")
            ui()
            return
        
        close(con)

        print(f"Connection {con} closed")
        ui()
        return

    ui()

        


ui()