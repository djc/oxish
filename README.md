# OxiSH: SSH server written in Rust

OxiSH is an SSH server written in Rust. It is a work in progress and not yet fit for usage.

Please don't publicize this project at its current stage. Funding to advance its development is welcome.

## Intended features

* Improved security track record
* Limit features to the most common
* Efficient -- low latency
* Usable as server and library

## Limitations

* Will only support modern clients
* May require a modern platform/Rust compiler (currently 1.75)
* No support for older cryptographic algorithms

## References to RFCs consulted during development

* [RFC 4251][rfc4251]: The Secure Shell (SSH) Protocol Architecture
* [RFC 4253][rfc4253]: The Secure Shell (SSH) Transport Layer Protocol
* [RFC 4344][rfc4344]: The Secure Shell (SSH) Transport Layer Encryption Modes
* [RFC 5656][rfc5656]: Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer
* [RFC 6668][rfc6668]: SHA-2 Data Integrity Verification for the Secure Shell (SSH) Transport Layer Protocol
* [RFC 8709][rfc8709]: Ed25519 and Ed448 Public Key Algorithms for the Secure Shell (SSH) Protocol
* [RFC 8731][rfc8731]: Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448
* [RFC 9142][rfc9142]: Key Exchange (KEX) Method Updates and Recommendations for Secure Shell (SSH)

[rfc4251]: https://www.rfc-editor.org/rfc/rfc4251
[rfc4253]: https://www.rfc-editor.org/rfc/rfc4253
[rfc4344]: https://www.rfc-editor.org/rfc/rfc4344
[rfc5656]: https://www.rfc-editor.org/rfc/rfc5656
[rfc6668]: https://www.rfc-editor.org/rfc/rfc6668
[rfc8709]: https://www.rfc-editor.org/rfc/rfc8709
[rfc8731]: https://www.rfc-editor.org/rfc/rfc8731
[rfc9142]: https://www.rfc-editor.org/rfc/rfc9142
