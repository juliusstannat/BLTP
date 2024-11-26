from client import BLTPClient
from bltp import State

if __name__ == "__main__":
    client = BLTPClient()
    sock = client.connect("127.0.0.1", 1111)
    """while client.connection.state != State.ESTABLISHED:
        pass"""
    client.send("Hello World")
    print(f"Received data: {client.receive(11)}")
    client.close()