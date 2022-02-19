import argparse
import p2sn


def main() -> bytes:
    argparser = argparse.ArgumentParser("P2SN")
    argparser.add_argument(
        "ip", action="store", help="IP address of the server"
    )
    argparser.add_argument(
        "port", action="store", help="Port of the server", type=int
    )
    argparser.add_argument(
        "msg", action="store", help="Message to send", nargs="+"
    )
    argparser.add_argument(
        "-q",
        "--quiet",
        action="count",
        help="Quiet output",
        dest="q",
        type=int,
    )
    argparser.add_argument(
        "--nbits",
        action="store",
        help="Number of bits to use for the key",
        dest="nbits",
        type=int,
        default=2048,
    )
    argparser.add_argument(
        "--accurate",
        action="store_true",
        help="Number of bits should be accurate",
        dest="accurate",
    )
    args = argparser.parse_args()
    client = p2sn.Client()
    client.logger.setLevel(args.q * 10 + 10)
    client.gen_keys(args.nbits, args.accurate)
    client.init((args.ip, args.port))
    rv = client.make_req(b" ".join(args.msg))
    print(rv)
    return rv


if __name__ == "__main__":
    main()
