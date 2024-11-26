from client import BLTPClient

if __name__ == "__main__":
    client = BLTPClient()
    sock = client.connect("127.0.0.1", 1111)
    print("----- SEND DATA not encrypted -----")
    client.send("Hello World")
    client.connection.enable_encryption()
    print("----- SEND DATA encrypted -----")
    client.send("Hello World")
    print("----- RECEIVE DATA encrypted -----")
    print(f"Received data: {client.receive(11)}")
    print("----- RECEIVED DATA encrypted -----")
    client.close()