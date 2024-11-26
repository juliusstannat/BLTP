from server import BLTPServer
from bltp import State

if __name__ == "__main__":
    server = BLTPServer()
    server.listen("127.0.0.1", 1111)
    new_con = server.wait_for_con()
    server.accept(new_con)
    while server.connections[0].state != State.ESTABLISHED:
        pass
    server.send(server.connections[0], "Hello World")
    print(server.receive(server.connections[0], 11))
    
    while server.connections[0].state != State.CLOSED:
        server.check_for_fin(server.connections[0])
        server.connections[0].receive_handler()
        b = server.check_for_closed(server.connections[0])
        if b:
            break