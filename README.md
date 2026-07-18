# OxiSH: SSH server written in Rust

[![Build status](https://github.com/djc/oxish/workflows/CI/badge.svg)](https://github.com/djc/oxish/actions?query=workflow%3ACI)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

OxiSH is an SSH server written in Rust. It is currently a minimum viable product and
not yet ready for production use. It is intended to be a secure, modern SSH server that supports post-quantum key exchange and FIPS-validated cryptography.

Please don't publicize this project at its current stage. Funding to advance its development is welcome.

## Features

- Only support modern cryptography, including hybrid post-quantum key exchange
- Support for FIPS-validated cryptography (via aws-lc-rs)
- Usable as server and library, including sans-I/O protocol implementation

If any features you need are missing, please open an issue or submit a pull request.

## Limitations

- Only supports Linux and macOS for now (looking for a Windows contributor)
- Only supports public key authentication for now
- No SFTP support yet
- Requires clients with support for mlkem768x25519-sha256 key exchange (OpenSSH 9.9+)
- No support for older cryptographic algorithms

## References to RFCs consulted during development

- [RFC 4251][rfc4251]: The Secure Shell (SSH) Protocol Architecture
- [RFC 4253][rfc4253]: The Secure Shell (SSH) Transport Layer Protocol
- [RFC 4344][rfc4344]: The Secure Shell (SSH) Transport Layer Encryption Modes
- [RFC 5647][rfc5647]: AES Galois Counter Mode for the Secure Shell Transport Layer Protocol
- [RFC 5656][rfc5656]: Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer
- [RFC 6668][rfc6668]: SHA-2 Data Integrity Verification for the Secure Shell (SSH) Transport Layer Protocol
- [RFC 8709][rfc8709]: Ed25519 and Ed448 Public Key Algorithms for the Secure Shell (SSH) Protocol
- [RFC 8731][rfc8731]: Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448
- [RFC 9142][rfc9142]: Key Exchange (KEX) Method Updates and Recommendations for Secure Shell (SSH)

[rfc4251]: https://www.rfc-editor.org/rfc/rfc4251
[rfc4253]: https://www.rfc-editor.org/rfc/rfc4253
[rfc4344]: https://www.rfc-editor.org/rfc/rfc4344
[rfc5647]: https://www.rfc-editor.org/rfc/rfc5647
[rfc5656]: https://www.rfc-editor.org/rfc/rfc5656
[rfc6668]: https://www.rfc-editor.org/rfc/rfc6668
[rfc8709]: https://www.rfc-editor.org/rfc/rfc8709
[rfc8731]: https://www.rfc-editor.org/rfc/rfc8731
[rfc9142]: https://www.rfc-editor.org/rfc/rfc9142
