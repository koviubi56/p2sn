"""
Peer to peer socket network
Copyright (C) 2021  Koviubi56

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import contextlib
import socket
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from collections import namedtuple
from enum import Enum, auto
from logging import Logger, basicConfig, getLogger
from threading import Thread
from types import MethodType
from typing import Any, Callable, Dict, Optional, Tuple, Union

import rsa

__version__ = "0.1.0"
__author__ = "Koviubi56"
__email__ = "koviubi56@duck.com"
__license__ = "GNU LGPLv3"
__copyright__ = "Copyright (C) 2021 Koviubi56"
__description__ = "Peer to peer socket network"
__url__ = "https://github.com/koviubi56/p2sn"

PUBKEY = b"P2SN:PUBKEY"
KEYCHECK = b"P2SN:KEYCHECK"
ERRORKEY = b"P2SN:ERRORKEY"
UNEXPECTEDERROR = b"P2SN:UNEXPECTEDERROR"
NULL = b"P2SN:NULL"

# ? Is this used anywhere? (TODO)
END_OF_BLOCK = b"\x03"

basicConfig(
    format="[%(levelname)s %(name)s %(asctime)s line: %(lineno)d] %(message)s",
    level=0,
)

SERVERKEYPAIR = namedtuple("SERVERKEYPAIR", "public private")
USERKEYPAIR = namedtuple("USERKEYPAIR", "public private")


def _assert(condition: bool, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)


class Request:
    """A Request."""

    class Type(Enum):
        """Types of requests."""

        MSG = auto()
        PUBKEY = auto()
        KEYCHECK = auto()
        NULL = auto()

    def __init__(
        self,
        msg: bytes,
        privkey: rsa.PrivateKey,
        *,
        clientsocket: socket.socket,
        address: Tuple[str, int],
    ) -> None:
        """
        Make a new request object.

        Args:
            msg (bytes): Message
            privkey (rsa.PrivateKey): Private key. Used for decrypting.
        """
        print(f"  [DEBUG] Got bytes: {msg!r}")
        self.og_msg = msg
        self.clientsocket = clientsocket
        self.address = address
        self.type = (
            self.Type.PUBKEY
            if self.og_msg == PUBKEY
            else self.Type.NULL
            if self.og_msg == NULL
            else self.Type.MSG
        )
        print(f"  [DEBUG] Got type: {self.type!r}")
        if self.type == self.Type.MSG:
            try:
                # By the way there is a 1 in 256^30
                # chance that the message will start with the
                # "-----BEGIN RSA PRIVATE KEY-----" header, but it isn't a key.
                self.msg = b64decode(self.og_msg)
                print(f"  [DEBUG] Got decoded msg: {self.msg!r}")
                if not self.msg.startswith(
                    b"-----BEGIN RSA PUBLIC KEY-----"
                ):
                    print("  [DEBUG] Msg isn't a public key")
                    self.msg = rsa.decrypt(self.msg, privkey)
            except (rsa.DecryptionError, rsa.pkcs1.CryptoError):
                print(
                    "\n[ERROR] There was an error while decrypting the"
                    " message! The exception will be reraised, but"
                    " **!DO NOT!** share the callstack!"
                )
                raise
            print("  [DEBUG] Decrypted message:", self.msg)
            if self.msg == KEYCHECK:
                print("  [DEBUG] Msg is KEYCHECK")
                self.type = self.Type.KEYCHECK

    def __repr__(self) -> str:
        """
        Return a string representation of the request.

        Returns:
            str: String representation of the request.
        """
        return f"<Request type={self.type!r} msg={self.msg!r}>"


class KeyedClass(ABC):
    """ABC for classes that use/need a public and a private key."""

    min_nbits: int = 1024
    pubkey: rsa.PublicKey
    privkey: rsa.PrivateKey

    @property
    def _keyed(self) -> bool:
        """
        Does the object have both keys?

        Returns:
            bool
        """
        return bool(getattr(self, "pubkey", None)) and bool(
            getattr(self, "privkey", None)
        )

    def gen_keys(self, nbits: int, accurate: bool) -> None:
        """
        Generate a new RSA keypair.

        Args:
            nbits (int): Number of bits. Must be above self.min_nbits\
 (defaults to 1024).
            accurate (bool): When generating the keys, the keysize should be\
 accurate? If this is False, it will be a bit quicker.

        Raises:
            ValueError: If nbits is too low.
        """
        if nbits < self.min_nbits:
            raise ValueError(
                f"nbits must be greater than or equal to {self.min_nbits}"
            )
        self.pubkey, self.privkey = rsa.newkeys(
            nbits, accurate=accurate
        )


class VerifyingError(RuntimeError):
    """Verification failed."""


class Server(KeyedClass):
    """
    This is an abstract class; a subclass must implement the "handle" method.
    A subclass will be able to run a P2SN server.
    To run the server, call the "start" method.
    """

    FAMILY = socket.AF_INET
    TYPE = socket.SOCK_STREAM
    TIMEOUT = 1.0
    BIND: Union[bytes, Tuple[Any, ...], str, None] = None
    LOGGER: Optional[Logger] = None

    def __init__(self) -> None:
        """Make a new Server object."""
        self.socket = socket.socket(self.FAMILY, self.TYPE)
        self.socket.settimeout(self.TIMEOUT)
        if self.BIND is None:
            self.socket.bind((socket.gethostname(), 5050))
        else:
            self.socket.bind(self.BIND)
        self.clientpubkey: Dict[
            str, Union[rsa.PublicKey, rsa.key.AbstractKey]
        ] = {}
        self.stopped = False
        self.logger = (
            getLogger(f"{__name__}:Server")
            if self.LOGGER is None
            else self.LOGGER
        )
        self._init = True

    def stop(self) -> None:
        """Stop the server. Warning: Threads cannot be stopped, so server can\
 refuse to stop!"""
        self.stopped = True

    def _recv_msg(
        self,
        clientsocket: socket.socket,
        address: Tuple[str, int],
    ) -> Request:
        """
        Receive a message from a client socket.

        Args:
            clientsocket (socket.socket): Client socket.
            address (Tuple[str, int]): Address of the client.

        Returns:
            Request: The request. If an error happens, it may be a NULL\
 request.
        """
        if self.stopped:
            return Request(
                NULL,
                self.privkey,
                clientsocket=clientsocket,
                address=address,
            )
        msg = b""
        try:
            data = clientsocket.recv(64_000)
        except (socket.timeout, TimeoutError):
            pass
        except (ConnectionAbortedError, ConnectionResetError):
            return Request(
                NULL,
                self.privkey,
                clientsocket=clientsocket,
                address=address,
            )
        if data or data.startswith(b"\x04"):
            new_data = data.split(b"\x04")[0]
            msg += new_data

        if msg == b"":
            return Request(
                NULL,
                self.privkey,
                clientsocket=clientsocket,
                address=address,
            )

        self.logger.info(
            f"Got message {msg!r} from client ({clientsocket.getpeername()})"
        )
        try:
            return Request(
                msg,
                self.privkey,
                clientsocket=clientsocket,
                address=address,
            )
        except Exception as er:
            self.logger.error(
                f"Error while decrypting and returning request: {er!r}"
            )
            clientsocket.sendall(ERRORKEY + b"\x04")
            return Request(
                NULL,
                self.privkey,
                clientsocket=clientsocket,
                address=address,
            )

    def _handle_pubkey(
        self, clientsocket: socket.socket, address: Tuple[str, int]
    ) -> Optional[bool]:
        """
        Handle [PUBKEY].

        Args:
            clientsocket (socket.socket): Client socket.
            address (Tuple[str, int]): Address
        """
        if self.stopped:
            return None
        self.logger.info(f"Received [PUBKEY] from client ({address})")
        self.logger.info(
            f"Sending server [pubkey] to client ({address})"
        )
        clientsocket.sendall(self.pubkey.save_pkcs1("PEM") + b"\x04")
        self.logger.info(
            f"Receiving client ({address}) [KEYCHECK]..."
        )
        r_ = self._recv_msg(clientsocket, address)
        if r_.type == Request.Type.KEYCHECK:
            self.logger.info(
                f"Received [KEYCHECK] from client ({address})"
            )
            self.logger.info(
                f"Sending [PUBKEY] to client ({address})"
            )
            clientsocket.sendall(PUBKEY + b"\x04")
            try:
                self.logger.info(
                    f"Receiving and loading client ({address}; {address[0]})"
                    " [pubkey]"
                )
                self.clientpubkey[
                    address[0]
                ] = rsa.PublicKey.load_pkcs1(
                    self._recv_msg(clientsocket, address).msg, "PEM"
                )
                self.logger.info(
                    f"[pubkey]: {self.clientpubkey[address[0]]!r};; n:"
                    f" {self.clientpubkey[address[0]].n!r}"
                )
            except Exception:
                self.logger.error(
                    f"Error while loading client ({address}) [pubkey]"
                )
                clientsocket.sendall(ERRORKEY + b"\x04")
                clientsocket.close()
                return None
            self.logger.info(
                f"Sending encrypted KEYCHECK to client ({address})"
            )
            self.reply(clientsocket, address, KEYCHECK)
            self.logger.info(
                "KEYCHECK sent, keyexchange is completed!"
            )
            return True
        else:
            self.logger.error(
                f"Didn't receive keycheck from client ({address!r});"
                f" got {r_.og_msg!r}"
            )
            clientsocket.sendall(ERRORKEY + b"\x04")
            clientsocket.close()
            return None

    def _handle(
        self, clientsocket: socket.socket, address: Tuple[str, int]
    ) -> None:
        """
        Internal handling new connections.

        Args:
            clientsocket (socket.socket): Client socket
            address (Tuple[str, int]): Address
        """
        if self.stopped:
            return
        self.logger.info(f"New connection from {address}")
        while True:
            self.logger.info(
                f"Receiving message from client ({address})..."
            )
            received_msg = self._recv_msg(clientsocket, address)
            if received_msg.type == Request.Type.NULL:
                self.logger.info(
                    f'"Received" [NULL] from client ({address}), terminating'
                    " connection..."
                )
                return
            with contextlib.suppress(AttributeError):
                if received_msg.msg == b"":
                    self.logger.info(
                        f"Received empty message from client ({address}), "
                        "terminating connection..."
                    )
                    return
            self.logger.info(
                f"Received [{received_msg.type}] {received_msg.og_msg!r} from"
                f" {address}"
            )
            if received_msg.type == Request.Type.PUBKEY:
                self.logger.info(f"Received [PUBKEY] from {address}")
                if self._handle_pubkey(clientsocket, address) is None:
                    self.logger.info(
                        f"Closing connection to {address}; error while key"
                        " exchange"
                    )
                    return
            elif received_msg.type == Request.Type.MSG:
                if received_msg.msg == b"":
                    self.logger.info(
                        f"Received empty message from {address}, terminating"
                        " connection..."
                    )
                    return
                self.logger.info(f"Received message from {address}")
                try:
                    self.handle(
                        received_msg,
                        self.make_reply(clientsocket, address),
                    )
                except Exception:
                    self.logger.error(
                        "Error while handling message", exc_info=True
                    )
                    self.reply(clientsocket, address, UNEXPECTEDERROR)

    def reply(
        self,
        clientsocket: socket.socket,
        address: Tuple[str, int],
        message: bytes,
    ) -> None:
        """
        Reply with an b64encoded, encrypted message.

        Args:
            clientsocket (socket.socket): Socket
            address (Tuple[str, int]): Address
            message (bytes): Clear text message
        """
        encrypted = rsa.encrypt(message, self.clientpubkey[address[0]])  # type: ignore  # noqa
        return clientsocket.sendall(b64encode(encrypted) + b"\x04")

    def make_reply(
        self, clientsocket: socket.socket, address: Tuple[str, int]
    ) -> Callable[[bytes], None]:
        """
        Make a reply function.

        Args:
            clientsocket (socket.socket): Socket
            address (Tuple[str, int]): Address

        Returns:
            Callable[[bytes], None]: Reply function
        """

        def reply(message: bytes) -> None:
            return self.reply(clientsocket, address, message)

        return reply

    @abstractmethod
    def handle(
        self,
        request: Request,
        reply: Callable[[bytes], None],
    ) -> Any:
        """
        Handle the request. A subclass should implement this method.

        Args:
            request (Request): The request
            reply (Callable[[bytes], None]): The reply function
        """
        return NotImplemented

    def start(self) -> None:
        """Start the server and listen."""
        _assert(
            self._keyed, "Server must have two keys before starting"
        )
        _assert(
            isinstance(getattr(self, "handle", None), MethodType),
            "Server must implement method handle",
        )
        _assert(
            getattr(self, "_init", None) is True,
            '__init__ must be ran. Did you overwrite it? If yes, run "return'
            ' super().__init__()" at the end',
        )
        self.logger.info("Starting server...")
        self.logger.info(f"Public key (n): {self.pubkey.n!r}")
        self.logger.info(
            f"Server is listening on {self.socket.getsockname()}"
        )
        self.socket.listen(5)
        while not self.stopped:
            try:
                (clientsocket, address) = self.socket.accept()
            except (socket.timeout, TimeoutError):
                continue
            self.logger.info(f"Got connection from {address}")
            thread = Thread(
                target=self._handle,
                name=f"Thread-P2SN-{address}",
                args=(clientsocket, address),
            )
            thread.start()


class Client(KeyedClass):
    """A client."""

    FAMILY = socket.AF_INET
    TYPE = socket.SOCK_STREAM
    TIMEOUT = 3.0
    LOGGER: Optional[Logger] = None
    serverpubkey: Union[rsa.PublicKey, rsa.key.AbstractKey]

    def __init__(self) -> None:
        """Make a new Client object."""
        self.socket = socket.socket(self.FAMILY, self.TYPE)
        self.socket.settimeout(self.TIMEOUT)
        self.logger = (
            getLogger(f"{__name__}:Client")
            if self.LOGGER is None
            else self.LOGGER
        )
        self.initialized = False

    def _recv_msg(
        self, socket_: Optional[socket.socket] = None, *, decode: bool
    ) -> bytes:
        """
        Receive message. Used internally.

        Args:
            decode (bool): Decode with Base64?
            socket_ (Optional[socket.socket], optional): Socket to use.\
 Defaults to None.

        Returns:
            bytes: Received bytes
        """
        socket_ = socket_ if socket_ is not None else self.socket
        msg = b""
        while True:
            try:
                data = socket_.recv(1024)
            except (socket.timeout, TimeoutError):
                break  # asdasdasdasdasdasdasd
            if vars().get("data", None) is not None:
                if not data:
                    break
                new_data = data.split(b"\x04")[0]
                msg += new_data
                if data.find(b"\x04") != -1:
                    break
        return b64decode(msg) if decode else msg

    def send_enc(self, msg: bytes) -> bytes:
        """
        Send encrypted and encoded msg, then return decrypted and decoded\
 response.

        Args:
            msg (bytes): Message to send.

        Returns:
            bytes: Response
        """
        _assert(
            self.initialized and self._keyed,
            "Client must have two keys and must be initialized",
        )
        self.logger.info(f"Sending encrypted text {msg!r}...")
        if not isinstance(self.serverpubkey, rsa.PublicKey):
            raise TypeError
        enc = rsa.encrypt(msg, self.serverpubkey)
        self.socket.sendall(b64encode(enc))
        self.logger.info("Decrypting response...")
        return rsa.decrypt(
            self._recv_msg(self.socket, decode=True), self.privkey
        )

    def init(
        self, address: Union[Tuple[str, int], str, bytes]
    ) -> bool:
        """
        Initialize connection.

        Args:
            address (Union[Tuple[str, int], str, bytes]): Server's address.

        Returns:
            bool: True if success
        """
        self.logger.info("Initializing connection...")
        self.initialized = False
        _assert(
            self._keyed, "Client must have two keys before starting"
        )

        self.logger.info(f"  Public key (n): {self.pubkey.n!r}")
        self.logger.info(f"  Connecting to {address!r}...")
        try:
            self.socket.connect(address)
        except socket.error:
            self.logger.exception(
                "    Cannot connect to server. IP/port misspelled or firewall?"
            )
            return False
        else:
            self.logger.info("    Connected successfully!")

        self.logger.info("  Key exchange...")
        self.logger.info("    Sending clear text message [PUBKEY]...")
        self.socket.sendall(PUBKEY + b"\x04")

        self.logger.info("    Loading server public key...")
        try:
            self.serverpubkey = rsa.PublicKey.load_pkcs1(
                self._recv_msg(self.socket, decode=False), "PEM"
            )
        except OSError:
            self.logger.error("    Server [pubkey] cannot be loaded")
            return False
        self.logger.info(
            f"      Got server publickey ({self.serverpubkey.n})"
        )

        enc = rsa.encrypt(KEYCHECK, self.serverpubkey)  # type: ignore  # noqa
        self.logger.info(
            f"    Sending encrypted message [KEYCHECK] {enc!r}..."
        )
        self.socket.sendall(b64encode(enc) + b"\x04")
        del enc

        self.logger.info("    Checking if we receive [PUBKEY]...")
        if (
            msg := self._recv_msg(self.socket, decode=False)
        ) != PUBKEY:
            self.logger.error(
                f"Server didn't ask for public key, it sent {msg!r}"
            )
            return False

        self.logger.info("      Received [PUBKEY]")
        self.logger.info(
            f"    Sending publickey {self.pubkey.save_pkcs1('PEM')!r}..."
        )
        self.socket.sendall(
            b64encode(self.pubkey.save_pkcs1("PEM")) + b"\x04"
        )

        self.logger.info(
            "    Checking if we receive encrypted [KEYCHECK]..."
        )
        __r = self._recv_msg(self.socket, decode=True)

        self.logger.info(f"      Received {__r!r}; decrypting...")
        _r = rsa.decrypt(__r, self.privkey)

        if _r != KEYCHECK:
            self.logger.error(
                f"We didn't receive encrypted [KEYCHECK], we got {_r!r};"
                " retrying..."
            )
            return False
        self.logger.info("      Received [KEYCHECK]")
        self.logger.info("    Key exchange is done!")
        self.initialized = True
        return True

    def make_req(self, msg: bytes) -> bytes:
        """
        Make a request.

        Args:
            msg (bytes): Message to send.

        Returns:
            bytes: Response
        """
        _assert(
            self.initialized,
            "Client must be initialized using method `init`",
        )
        _assert(
            self._keyed, "Client must have two keys before starting"
        )
        self.logger.info(f"Sending encrypted message {msg!r}...")
        rv = self.send_enc(msg)
        self.logger.info("Got response!")
        return rv


class TestServer(Server):
    """This class is intended for testing purposes only! This class must not\
 be used in production; please inherit from `Server` instead."""

    def handle(self, *_: Any, **__: Any) -> Any:
        """
        This class is intended for testing purposes only! This class must not\
 be used in production; please inherit from `Server` instead.

        Returns:
            str
        """
        return self.__doc__
