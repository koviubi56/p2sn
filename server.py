from typing import Callable

import p2sn


class MyServer(p2sn.Server):
    def handle(
        self, request: p2sn.Request, reply: Callable[[bytes], None]
    ) -> None:
        print(f"{request.address} sent: {request.og_msg.decode()}")
        reply(b'Hi! You sent me "' + request.msg + b'"')


def main() -> None:
    s = MyServer()
    s.gen_keys(p2sn.RECOMMENDED_NBITS, p2sn.RECOMMENDED_ACCURACY)
    s.start()


if __name__ == "__main__":
    main()
