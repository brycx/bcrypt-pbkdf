### About

A pure Rust implementation of the `bcrypt_pbkdf` password hashing algorithm.

It is mostly based on the work done in [rust-crypto](https://docs.rs/rust-crypto/0.2.36/crypto/bcrypt_pbkdf/fn.bcrypt_pbkdf.html).
As such, this library is tested with all test vectors provided in [rust-crypto](https://github.com/DaGenix/rust-crypto/blob/master/src/bcrypt_pbkdf.rs).

### Security
This library has at no point received any formal cryptographic/security audit. It
should be used at own risk.

### Example
```rust
extern crate bcrypt_pbkdf;

let password = "password".as_bytes();
let salt = "salt".as_bytes();
let mut out = [0u8; 64];

bcrypt_pbkdf::bcrypt_pbkdf(password, salt, 100, &mut out);
```

### References
- [rust-crypto](https://github.com/DaGenix/rust-crypto)
- [OpenBSD](https://man.openbsd.org/bcrypt_pbkdf.3)
- [pyca](https://github.com/pyca/bcrypt)

### License
`bcrypt-pbkdf` is licensed under the MIT license. See the `LICENSE` file for more information.
