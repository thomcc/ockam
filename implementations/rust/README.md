# Ockam in Rust

[Ockam](https://github.com/ockam-network/ockam#readme) is a suite of tools,
programming libraries and infrastructure that make it easy to build devices
that communicate securely, privately and trustfully with cloud services and
other devices.

This folder contains a collection of Rust [crates](./ockam/) that implement
various [features of Ockam](https://github.com/ockam-network/ockam#features).

## Features

| Feature             | Maturity                      | Crate             | Crate                                      |
| --------------------|:------------------------------| -----------------:|--------------------------------------------|
| Node - Standard     | ![experimental][preview]      | ockam_node        | Runs Ockam Workers                         |
| Workers             | ![experimental][preview]      | ockam_node        | Concurrent actors that respond to messages |
| Routing             | ![experimental][experimental] |                   |                                            |
| Transports          | ![experimental][experimental] |                   |                                            |
| Transport - TCP     | ![experimental][experimental] |                   |                                            |
| Entities            | ![experimental][experimental] |                   |                                            |
| Profiles            | ![experimental][experimental] |                   |                                            |
| Vaults              | ![experimental][experimental] |                   |                                            |
| Vault - Software    | ![experimental][experimental] |                   |                                            |
| Vault - ATECC608A   | ![experimental][experimental] |                   |                                            |
| Credentials         | ![experimental][planned]      |                   |                                            |

[planned]: https://img.shields.io/badge/Status-Planned-EEEEEE.svg?style=flat-square
[experimental]: https://img.shields.io/badge/Status-Experimenal-FFD932.svg?style=flat-square
[preview]: https://img.shields.io/badge/Status-Preview-6BE3CF.svg?style=flat-square
[stable]: https://img.shields.io/badge/Status-Stable-81D553.svg?style=flat-square
[depricated]: https://img.shields.io/badge/Status-Stable-EC6D57.svg?style=flat-square
