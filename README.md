# nyx

[![Travis](https://travis-ci.com/evenorog/nyx.svg?branch=master)](https://travis-ci.com/evenorog/nyx)
[![Crates.io](https://img.shields.io/crates/v/nyx.svg)](https://crates.io/crates/nyx)
[![Docs](https://docs.rs/nyx/badge.svg)](https://docs.rs/nyx)

Small `no-std` implementation of the TOTP algorithm.

Only SHA-1 is supported.

```rust
use std::time::SystemTime;

let time = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
let _ = nyx::generate(b"12345678901234567890", time);
```

Based on the implementation from [totp-rs](https://crates.io/crates/totp-rs).

### License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
