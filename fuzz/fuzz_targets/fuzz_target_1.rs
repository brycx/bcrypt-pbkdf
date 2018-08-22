#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate bcrypt_pbkdf;
extern crate crypto;

use crypto::bcrypt_pbkdf::bcrypt_pbkdf;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let mut pass = data.to_vec();
    let mut salt = data.to_vec();
    pass.push(0u8);
    salt.push(0u8);

    let mut out_crypto = [0u8; 64];
    let mut out_this = [0u8; 64];
    bcrypt_pbkdf::bcrypt_pbkdf(&pass, &salt, 1024, &mut out_this);
    bcrypt_pbkdf(&pass, &salt, 1024, &mut out_crypto);
    assert_eq!(out_this.as_ref(), out_crypto.as_ref());

});
