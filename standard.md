# P2SN standard

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

P2SN provides an encrypted tunnel between the client and the server. It achives this using RSA encryption.

Note, that we used "it" for the client and the server. It is because we expect them to be computers.

## Important things used in this standard

- `b""` is a _bytes string_. Anything that is inside the double-quotes should be encoded to bytes using UTF-8. Thus `b"fox"` would be the bytes `66 6f 78` hex or `102 111 120` dec. These bytes can be stored in any way.
- `\xNN` is a character's hex number. Only `\x04` will be used in this standard, which is `04` hex or `4` dec, [_End of Transmission_](https://theasciicode.com.ar/ascii-control-characters/eot-end-of-transmission-diamonds-card-suit-ascii-code-4.html).
- _P2SN Base64_ is just normal Base64 but the alternative characters are "+" and "/".

## The standard

The server and the client MUST have an RSA public and private key. Those key SHOULD be at least 1024 bits. The server MUST NOT change its public or private key while it is connected to a client. The client MUST NOT change its public or private key while it is connected to a server.

If an unexpected exeption if raised, the server MAY send b"P2SN:UNEXPECTEDERROR" ([UNEXPECTEDERROR]) to the client (so `50 32 53 4e 3a 55 4e 45 58 50 45 43 54 45 44 45 52 52 4f 52`). But if an exception is thrown while receiving/converting/doing something with the client's public key, the server MUST send b"P2SN:ERRORKEY" ([ERRORKEY]) instead (this is REQUIRED, not like the [UNEXPECTEDERROR], `50 32 53 4e 3a 45 52 52 4f 52 4b 45 59`).

### 1. Connecting

To send messages using P2SN, the client MUST connect to the server.

Then the client MUST send `b"P2SN:PUBKEY"` ([PUBKEY]) + `\x04` to the server (so `50 32 53 4e 3a 50 55 42 4b 45 59 04` hex).

If the server receives a [PUBKEY] (specified above), it MUST responde with its public key, encoded with PKCS1 PEM. The message MUST be encoded with P2SN Base64 (specified above) and there MUST be a(n) `\x04` at the end of the message. The client MUST store this public key somehow.

Then the client MUST encrypt `b"P2SN:KEYCHECK"` ([KEYCHECK], `50 32 53 4e 3a 4b 45 59 43 48 45 43 4b` hex) with the server's public key that it just got. The client MUST send it to the server encoded with P2SN Base64 (specified above) and there MUST be a(n) `\x04` at the end of the message.

If the server receives a message after sending its public key, it MUST check if the message with removing the `\x04` at the end, and decoding with P2SN Base64 (specified above), decrypted with the server's private key is the same as [KEYCHECK] (specified above). If it doesn't match, it MUST responde with `b"P2SN:ERRORKEY"` ([ERRORKEY]) + `\x04` to the client (so `50 32 53 4e 3a 45 52 52 4f 52 4b 45 59 04` hex). If it does match, the server MUST responde with [PUBKEY] (specified above) to the client.

If the client receives a [PUBKEY] (specified above), it MUST responde with its public key, encoded with PKCS1 PEM. The message MUST be encoded with P2SN Base64 (specified above) and there MUST be a(n) `\x04` at the end of the message. The server MUST store this public key somehow.

Then the server MUST encrypt [KEYCHECK] (specified above) with the client's public key that it just got. The server MUST send it to the client encoded with P2SN Base64 (specified above) and there MUST be a(n) `\x04` at the end of the message.

If the client receives a message after sending its public key, it MUST check if the message with removing the `\x04` at the end, and decoding with P2SN Base64 (specified above), decrypted with the client's private key is the same as [KEYCHECK] (specified above). If it doesn't match, it MUST responde with `b"P2SN:ERRORKEY"` ([ERRORKEY]) + `\x04` to the server (so `50 32 53 4e 3a 45 52 52 4f 52 4b 45 59 04` hex). If it does match, the key exchange is done!

### 2. Sending messages

Before sending or receiving any messages, the client and the server MUST be connected (specified above).

The "sender" encrypts the message with the "receiver"'s public key. The "sender" encodes it with P2SN Base64 (specified above) and adds a(n) `\x04` at the end. The "sender" sends this message to the "receiver".

The "receiver" removes the `\x04` at the end. The "receiver" decodes the got message with P2SN Base64 (specified above). The "receiver" decrypts the message with the "receiver"'s private key. If the "receiver" is the server, it MUST responde; if it's the client, it MAY responde.
