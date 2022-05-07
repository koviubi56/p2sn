# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Added

- Added `keyboard` as a requirement [4eb50e9](https://github.com/koviubi56/p2sn/commit/4eb50e96f7d341c04fe9bc72037eb8e4bbbc03b4#diff-4d7c51b1efe9043e44439a949dfd92e5827321b34082903477fd04876edb7552R1)
- Added methods: `Request._handle_msg`, `Server._handle_empty`, and `Server._handle_msg` [b447ee3](https://github.com/koviubi56/p2sn/commit/b447ee3ee5a9af2635b79d8a5727c229541fbdf0)

## [0.3.0-beta.2] - 2022-04-22

## Added

- **! Added the P2SN standard** [201cc99](https://github.com/koviubi56/p2sn/commit/201cc9934b183f6a44c8047e3ceec5e2c7f25016#diff-80bce7270a622fc11d4c0242a2d342937ec565661e8d98f4a2d2d66f43d38157)
- **! Added CTRL+C support** [c5b6afe](https://github.com/koviubi56/p2sn/commit/c5b6afeaea2c9fb9f1dc857938a79a1f77545938#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edR486-R506)

## Changed

- `server.py` now replies with the original message too. [aaa67b6](https://github.com/koviubi56/p2sn/commit/aaa67b6c60cefcde85b51e264e46e505902ad032#diff-791d4d41d3718d15d49180f3aacc8370b8cab07383f0d35b2713651cc0adfe46R10-R11)
- Changed `setup.py` [d8e49a5](https://github.com/koviubi56/p2sn/commit/d8e49a511b7b50ad36767ab4bbc3b60356401359#diff-60f61ab7a8d1910d86d9fda2261620314edcae5894d5aaa236b821c7256badd7)

## Removed

- Removed not used variables (`END_OF_BLOCK`, `SERVERKEYPAIR`, `CLIENTKEYPAIR`) [5b6dfff](https://github.com/koviubi56/p2sn/commit/5b6dfff29286e72901cb1ca8c815a21dbe3245e2#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edL45-L54)

## Fixed

- **In `Server.send_enc`, before this fix, we did _not_ put `\x04` at the end of the message. Strangely this never caused any problems.**
- **The altchars `+` and `/` are now hard-coded into Base64 encoding and decoding.** [36232e9](https://github.com/koviubi56/p2sn/commit/36232e9f38a3d4fe8d75ca7a757acd3e26771005)
- **Fixed `server.py`, so it now uses _the new arguments_.** [aaa67b6](https://github.com/koviubi56/p2sn/commit/aaa67b6c60cefcde85b51e264e46e505902ad032#diff-791d4d41d3718d15d49180f3aacc8370b8cab07383f0d35b2713651cc0adfe46R8)
- In `Server._recv_msg`, timeout errors (`TimeoutError` and `socket.timeout`) were moved to the other errors in the try-except block. Before this fix, if a timeout error happened, it would `pass`, and raise a NameError, since `data` is not defined.

## [0.3.0-beta.1] - 2022-04-15

## Added

- **Added `standard.md`**
- Added `.bandit`, `.editorconfig`, `.pre-commit-config.yaml`, `.travis.yml`, `bandit.yml`

## Changed

- Changed `CONTRIBUTING.md`, `setup.cfg`, `src/p2sn/__init__.py`
- Changed from `assert` to `if not` in `client.py`
- Changed from `>=` to `==` in `requirements.txt`

## Removed

- Removed `.github/workflows/tests.yml`, `requirements_dev.txt`, `tests/`
- Removed lots of stuff from `setup.py`

## [0.2.0] - 2022-04-14

### Added

- **! `Server` now requires `reply` in `handle`** [62718fd](https://github.com/koviubi56/p2sn/commit/62718fd2011263e4920ef7fbcd10da6c579d3c33#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edR446)
- **`Server` now requires `address` in `_recv_msg`** [62718fd](https://github.com/koviubi56/p2sn/commit/62718fd2011263e4920ef7fbcd10da6c579d3c33#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edR215)
- **`Request` now requires `clientsocket` and `address` in `__init__`** [62718fd](https://github.com/koviubi56/p2sn/commit/62718fd2011263e4920ef7fbcd10da6c579d3c33#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edR70-R77)
- **If an unexpected error happens at the server side, it will reply with `b"P2SN:UNEXPECTEDERROR"` (`[UNEXCPECTEDERROR]`)** [c48e691](https://github.com/koviubi56/p2sn/commit/c48e69185adf186e8fb3defe120086f9d8297753#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edR402-R411)
- `Server.start` will check if you ran `Server.__init__` [c48e691](https://github.com/koviubi56/p2sn/commit/c48e69185adf186e8fb3defe120086f9d8297753#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edR473-R477)
- `Request` has a `__repr__` [d9c59ec](https://github.com/koviubi56/p2sn/commit/d9c59ec3b05d5f07f16ed41871993c6463805f2a#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edR112-R120)

### Changed

- Changed the diagram in the [README](README.md) to mermaid. [32d8218](https://github.com/koviubi56/p2sn/commit/32d821830354e7e7c51c0d775a25f7a4d62f9df9#diff-b335630551682c19a781afebcf4d07bf978fb1f8ac04c6bf87428ed5106870f5R20-R31)
- Better `[NULL]` handling, trying to catch `[NULL]` more times at more places. [62718fd](https://github.com/koviubi56/p2sn/commit/62718fd2011263e4920ef7fbcd10da6c579d3c33)

### Removed

- **! The arguments `clientsocket` and `address` were _removed_ from `Server.handle`** [62718fd](https://github.com/koviubi56/p2sn/commit/62718fd2011263e4920ef7fbcd10da6c579d3c33#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edL369-L370)

## [0.1.0] - 2022-01-09
