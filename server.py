import socket
from typing import Tuple
import p2sn


class MyServer(p2sn.Server):
    def handle(
        self,
        clientsocket: socket.socket,
        address: Tuple[str, int],
        request: p2sn.Request,
    ) -> None:
        print(f"{address} sent: {request.og_msg.decode()}")
        self.reply(clientsocket, address, b"Hi!")


def main():
    print(f"IP: {socket.gethostbyname(socket.gethostname())}")
    s = MyServer()
    print(f"IP & port: {s.socket.getsockname()}")
    print(1)
    s.gen_keys(2048, False)
    print(2)
    s.start()
    print(3)


if __name__ == "__main__":
    main()
