import p2sn


def main():
    c = p2sn.Client()
    c.gen_keys(2048, False)
    if not c.init((input(">>> IP: "), int(input(">>> Port: ")))):
        raise RuntimeError("Could not connect to server")
    while True:
        print(c.make_req(bytes(input(">>> Message: "), "utf-8")))


if __name__ == "__main__":
    main()
