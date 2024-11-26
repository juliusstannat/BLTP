import logging
import sys
from client import BLTPClient
from server import BLTPServer
import socket

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # change to ERROR for production

i = 1

possible_cons = {}
connections = {}

client = None
server = None

def ui():
    global i
    global client
    global server

    # Suche als Server nach neuen Verbindungen
    if server is not None:
        server.sock.timeout(2)

        new_con = server.wait_for_con() # warte auf neue Verbindung für 2 Sekunden
        if new_con is not None and new_con not in possible_cons.values() and new_con not in [(con.peer_address, con.peer_port) for con in server.connections]: # wenn neue Verbindung gefunden und noch nicht in possible_cons
            print(f"Possible connection: {new_con} as {i}")
            possible_cons[i] = new_con
            i += 1
        
        # Suche nach FIN-Paketen und schließe/lösche Verbindungen
        for con in server.connections: 
            server.check_for_fin(con)
            
            if server.check_for_closed(con):
                print("-----------------------------------")
                print(f"Connection {list(connections.keys())[list(connections.values()).index(con)]} closed")
                print("-----------------------------------")

                del connections[list(connections.keys())[list(connections.values()).index(con)]]
                
                server.sock.timeout(None)

                ui()
                return
            
            #con.listen_for_ack()
            
        server.sock.timeout(None)
    
    """if client is not None:
        client.sock.timeout(2)
        client.connection.listen_for_ack()
        if client is not None:
            client.sock.timeout(None)"""
                        
    cmd = input("") # Eingabeaufforderung

    # Befehle

    # CONNECT (remote IP address, remote port)
    if cmd.startswith("CONNECT"):
        # Überprüfe ob Eingabe korrekt ist und trenne IP-Adresse und Port
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
        except socket.error:
            logging.error("IP address is not correct.")
            ui()
            return

        # Überprüfe ob Port gültig ist
        if (remote_port) < 1024 or (remote_port) > 65535:
            logging.error("Port is not valid")
            ui()
            return
        
        # Erstelle Client und verbinde mit Server (remote IP-Adresse, remote Port)
        client = BLTPClient("192.168.1.3", 1234) # <-- this is the address and port of the client

        print("-----------------------------------")
        print("Connection identifier: 0")
        print("-----------------------------------")
        client.connect(remote_ip, remote_port)

        ui()
        return
    
    # LISTEN (local port [, local IP address])
    if cmd.startswith("LISTEN"):
        local_ip = '192.168.1.3'

        # Überprüfe ob Eingabe korrekt ist und trenne IP-Adresse und Port, falls IP-Adresse angegeben
        try:
            local_port = int(cmd.split(" ")[1])
        except IndexError:
            logging.error("wrong format: LISTEN (local port [, local IP address])")
            ui()
            return
        except ValueError:
            logging.error("wrong format: LISTEN (local port [, local IP address])")
            ui()
            return
        ## verify if port is valid
        if (local_port) < 1024 or (local_port) > 65535:
            logging.error("Port is not valid")
            ui()
            return
        
        # Erstelle Server und warte auf Verbindungen
        server = BLTPServer()
        server.listen(local_ip, local_port)

        # Warte bis neue Verbindung vorhanden ist
        new_con = server.wait_for_con()
        
        print("-----------------------------------")
        print(f"Possible connection: {new_con} as {i}")
        print("-----------------------------------")
        possible_cons[i] = new_con
        i += 1

        ui()
        return
    
    # ACCEPT (local socket name)
    if cmd.startswith("ACCEPT"):

        # Überprüfe ob Eingabe korrekt ist
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
        
        # Überprüfe ob Verbindung möglich ist
        if possible_cons.get(con) == None:
            logging.error("Connection not possible")
            ui()
            return
        
        print("-----------------------------------")
        print(f"Connection {con} accepted")
        print("-----------------------------------")

        # Verbindung akzeptieren
        connections[con] = server.accept(possible_cons[con])
        del possible_cons[con]



        ui()
        return

    # SEND (local connection name, data [, timeout])
    if cmd.startswith("SEND"):

        # Überprüfe ob Eingabe korrekt ist und trenne Verbindungsname und Daten
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
        
        # Überprüfe ob Timeout angegeben ist
        try:
            timeout = int(cmd.split(" ")[3])
            if timeout < 0:
                logging.error("timeout must be a positive integer")
                ui()
                return
            if con == 0:
                client.timeout(timeout)
            else:
                server.timeout(timeout)
        except Exception as e:
            pass

        # Sende Daten
        sent_data = None
        if con == 0 and client is not None:
            sent_data = client.send(msg)
        elif con != 0 and server is not None:
            sent_data = server.send(connections[con], msg)
        
        if sent_data is not None:
            print(f"Sent: {sent_data}")

    
        ui()
        return
    
    # RECEIVE (local connection name, byte count, [timeout])
    if cmd.startswith("RECEIVE"):
        timeout = None

        # Überprüfe ob Eingabe korrekt ist und trenne Verbindungsname und Byteanzahl
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
        
        # Überprüfe ob Timeout angegeben ist
        if len(cmd.split(" ")) == 4:
            timeout = int(cmd.split(" ")[3])
            if timeout < 0:
                logging.error("timeout must be a positive integer")
                ui()
                return
        
        # Empfange Daten
        received = None
        if con == 0 and client is not None: 
            received = client.receive(byte_count, timeout)
        elif con != 0 and server is not None:
            received = server.receive(connections[con], byte_count, timeout)

        if received is not None:
            print(f"Received: {received}")

        ui()
        return
    
    # CLOSE (local connection name)
    if cmd.startswith("CLOSE"):
        # Überprüfe ob Eingabe korrekt ist und trenne Verbindungsname
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
        
        if client is None or con != 0:
            logging.error("Server can't close connection")
            ui()
            return
        
        # Schließe Verbindung
        client.close()

        
        print(f"Connection {con} closed")
        ui()
        return
    
    # CAESAR
    if cmd.startswith("CAESAR"):
        # Aktivierte Verschlüsselung
        if client is not None:
            client.connection.enable_encryption()
            print("Encryption enabled")
        else:
            logging.error("Client not connected")
        
        ui()
        return

    ui()

        


ui()