"""
Tests for P2SN.
"""
from base64 import b64encode
from functools import lru_cache

import pytest
import rsa
import p2sn

cache = lru_cache(maxsize=None)

# pylint: disable=missing-function-docstring


@cache
def serverkeypair() -> p2sn.SERVERKEYPAIR:
    """Server keypair"""
    s = p2sn.TestServer()
    s.gen_keys(s.min_nbits * 2, False)
    return p2sn.SERVERKEYPAIR(s.pubkey, s.privkey)


@pytest.fixture(scope="module")
def skp() -> p2sn.SERVERKEYPAIR:
    """Server keypair"""
    return serverkeypair()


@cache
def userkeypair() -> p2sn.USERKEYPAIR:
    """Client keypair"""
    s = p2sn.Client()
    s.gen_keys(s.min_nbits * 2, False)
    return p2sn.USERKEYPAIR(s.pubkey, s.privkey)


@pytest.fixture(scope="module")
def ckp() -> p2sn.USERKEYPAIR:
    """Client keypair"""
    return userkeypair()


class TestRequests:
    """Tests for P2SN requests."""

    @pytest.mark.parametrize(
        "msg, typ",
        [
            (
                b64encode(
                    rsa.encrypt(
                        b"-The quick brown fox jumps over the lazy dog. ;)-",
                        serverkeypair().public,
                    )
                ),
                p2sn.Request.Type.MSG,
            ),
            (b"P2SN:PUBKEY", p2sn.Request.Type.PUBKEY),
            (
                b64encode(
                    rsa.encrypt(
                        b"P2SN:KEYCHECK", serverkeypair().public
                    )
                ),
                p2sn.Request.Type.KEYCHECK,
            ),
        ],
    )
    def test_types(
        self,
        skp: p2sn.SERVERKEYPAIR,  # pylint: disable=redefined-outer-name
        msg: bytes,
        typ: p2sn.Request.Type,
    ) -> None:
        r = p2sn.Request(
            msg, skp.private, clientsocket=None, address=None
        )
        assert r.type == typ  # nosec
        assert r.og_msg == msg  # nosec
