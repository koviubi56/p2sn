# p2sn
P2SN is a ***P***eer to ***p***eer, encrypted ***s***ocket ***n***etwork written in python.
P2SN uses asymmetric/public key encription ([RSA](https://pypi.org/project/rsa/)) for all\* communication between the two peers.
P2SN uses Base64 (with the '+' and '/' characters) to encode and decode everything\*\*.

\*: Everything, except PUBKEY, pubkey, KEYERROR, and NULL.

\*\*: Everything, except PUBKEY, KEYERROR, and NULL

## How does it work
### Key exchange
```text
SERVER                     CLIENT
  ┌─What's your public key?─┘
  └─It's 12642607...────────┐
  ┌─[KEYCHECK]──────────────┘
  └─What's your public key?─┐
  ┌─It's 12642607...────────┘
  └─[KEYCHECK]──────────────┐
                          Done!
```

*b"..."* means a bytes string.
*\x04* marks the end of the message, [ASCII code 4](https://theasciicode.com.ar/ascii-control-characters/eot-end-of-transmission-diamonds-card-suit-ascii-code-4.html).
*[KEYCHECK]* is simply used for checking if the peer received the right key correctly. The bytes b"P2SN:KEYCHECK" are encrypted.
*[ERRORKEY]* is b"P2SN:ERRORKEY"

The client and the server must have a public, and a private RSA key. Minimum recommended keysize: 1024 bits.

- Client connects to server.
- Client sends b"P2SN:PUBKEY\x04"
- Server sends its public key saved with [pkcs1](https://en.wikipedia.org/wiki/PKCS_1) [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) encoded with Base64 + b"\x04"
- Client sends encrypted [KEYCHECK] encoded with Base64 + b"\x04"
  - If error happens, server replies with [ERRORKEY] + b"\x04"
- Server sends b"P2SN:PUBKEY\x04"
- Client sends its public key saved with [pkcs1](https://en.wikipedia.org/wiki/PKCS_1) [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) encoded with Base64 + b"\x04"
- Server sends encrypted [KEYCHECK]
  - If error happens, client does nothing.

### Communicating

The client must be initialized. The client is initialized is its connected to the server, and the key exchange successfully happened (see above).

- Client sends message encrypted with the server's public key, encoded with Base64 + b"\x04"
- Server replies with message encrypted with the client's public key, encoded with Base64 + b"\x04"
