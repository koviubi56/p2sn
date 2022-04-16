import socket
from typing import Callable
import p2sn


class MyServer(p2sn.Server):
    def handle(
        self, request: p2sn.Request, reply: Callable[[bytes], None]
    ) -> None:
        print(f"{request.address} sent: {request.og_msg.decode()}")
        reply(b"Hi!")


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
