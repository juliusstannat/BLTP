# BLTP

Das BLTP (Bachelor-Lab-Transport-Protocol) ist eine simple Erweiterung für die Datenuebertragung basierend auf UDP.

## Inhaltsverzeichnis

1. [Usage](#Usage)
2. [Features](#features)
4. [Tests](#tests)
5. [Kontakt](#kontakt)


## Verwendung

Um die Implementation für Server und Client laufen zu lassen, muessen zwei Instanzen von ui.py gestartet werden. Dabei sehen die Konsoleneingaben wie folgt aus: 

	Starten bzw Handshake initialisieren:



Oeffne 2 Terminal-Fenster: T1 (Server) und T2 (Client)



    T1: “python ui.py” (fuer Windows) oder “python3 ui.py” (fuer MacOS)
    T2: Analog zu 2

    T1 (Server): LISTEN [local port]

    T2 (Client): CONNECT [remote IP address] [remote port]			
    ! Leerzeichen zwischen den beiden Eingaben

    T1 - Ausgabe (Server): Possible connection: (“remote_address', peer_port) as [Connection identifier]

    T1 (Server): ACCEPT [Connection identifier]		
    ! Bei einer einzigen Verbindung ist der connection identifier {1} auf der Serverseite und {0} auf der Clientseite

“Der Handshake wird nun ausgeführt und beide Kommunikationsendpunkte sollten im Normalfall in ESTABLISHED sein.”


Pakete versenden: 

    Paket senden: SEND [Connection identifier] [message]

    Pakete empfangen RECEIVE [Connection identifier] [Byte count]

    Beispiel: Client Connection identifier = 0, Server Connection identifier = 1

    T2: SEND 0 Hello World! 

    T2 - Ausgabe: “sent: 5, wobei 5 als Byte count steht”
    
    T1: RECEIVE 1 5 

“Paket wurde nun empfangen und und ein Ack wird direkt hinterher geschickt”



Close Connection: 
“ CLOSE wird vom CLIENT initialisiert”

    T2:  CLOSE [Connection identifier]
    T1: RECEIVE [Connection identifier] [Byte count]

“Verbindung wurde nun Client-seitig geschlossen”


Woertliche Beispielabfolge:

Sollte ein Peer keine weiteren Aktionen durchführen, einfach ENTER drücken, damit dies als input genommen wird und die Endlosschleife verlassen wird (von input("")).

Eine Beispielabfolge von Befehlen könnte folgendermaßen aussehen:

- Oeffne eine ui.py für den Server und gebe LISTEN 1111 ein.
- Dann öffne eine ui.py Instanz für den Client und verbinde die Instanz mit dem Server: CONNECT 127.0.0.1 1111.
- Akzeptiere die Verbindung mit ACCEPT 1 (lokale PeerID) als Server und sende eine Nachricht "Hello World!". 
- Empfange die Nachricht als Client mit RECEIVE 0 (= lokale PeerID) 12 (= Anzahl Bytes der Nachricht) 5 (= Timeout von 5 Sekunden, optional).
Anschließend schließe die Verbindung (clientseitig) mit CLOSE 0.

- Extension
Um die Extension zu verwenden muss man als Client den Befehl CAESAR eingeben, dann wird die Verschlüsselung aktiviert.



## Tests 

### Handshake-Test

Ueberprueft die korrekte Funktionsweise des Verbindungsaufbaus. Der erste Teil des Tests ueberprueft, ob sich sowohl Client als auch Server nach dem Handshake im Zustand ESTABLISHED befinden. Im zweiten Teil des Tests wird der Handshake mit einer ungueltigen Acknowledgement-Nummer initialisiert. Der Verbindungsaufbau sollte fehlschlagen.

#### Schritte

Oeffne zwei Terminal Tabs.

Starte test_handshake_server.py auf dem ersten Tab:
	
	python3 test_handshake_server

Starte test_handshake_client.py auf dem zweiten Tab:

	python3 test_handshake_client

Nach Vollendung dieser Schritte starten jeweils zwei Tests, die mit Eingabe der Enter-Taste bestaetigt werden muessen. Dabei ist jeweils zuerst der Test in test_handshake_server.py zu bestaetigen und dann der Test in test_handshake_client.py.

### FIN-Test

Testet den korrekten Verbindungsabbau.

#### Schritte
 
Oeffne zwei Terminal Tabs:

Starte test_fin_server.py auf dem ersten Tab:
	
	python3 test_fin_server

Starte test_fin_client.py auf dem zweiten Tab:

	python3 test_fin_client

### Packet-Test

Ueberprueft die Kodierung und Dekodierung der Integer Fields.

#### Schritte

Starte test_packets.py:
	
	python3 test_packets.py