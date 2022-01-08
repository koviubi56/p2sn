# p2sn
P2SN is a ***P***eer to ***p***eer, encrypted ***s***ocket ***n***etwork written in python.
P2SN uses asymmetric/public key encription ([RSA](https://pypi.org/project/rsa/)) for all communication between the two peers.

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

*[KEYCHECK]* is simply used for checking if the peer received the right key correctly.
*b"..."* means a bytes string.
*\x04* marks the end of the message, [ASCII code 4](https://theasciicode.com.ar/ascii-control-characters/eot-end-of-transmission-diamonds-card-suit-ascii-code-4.html).

Client connects to server.
Client sends b"P2SN:PUBKEY\x04"
Server sends its public key saved with [pkcs1](https://en.wikipedia.org/wiki/PKCS_1) [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
Client sends [WIP...]
