# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **! The  arguments `clientsocket` and `address` were _removed_ from `Server.handle`** [62718fd](https://github.com/koviubi56/p2sn/commit/62718fd2011263e4920ef7fbcd10da6c579d3c33#diff-8740706cc305b0ad918cd3c3385650f61d71d11ce22fabc08f7afa184fae64edL369-L370)

## [0.1.0] - 2022-01-09
