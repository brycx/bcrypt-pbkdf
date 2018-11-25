// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_std]

//! This implements the `bcrypt_pbkdf` password hashing algorithm.
//!
//! # Errors:
//! - If either `password`, `salt` or `hash_out` are empty
//! - If `hash_out` length is greater than 1024
//! - If zero rounds are selected
//!
//! # Secrity:
//! It is strongly recommnded to use a salt generated with a CSPRNG and select a number of rounds
//! that is greater than 50.

#[cfg(test)]
#[macro_use]
extern crate std;
mod bcrypt_hash;
extern crate blowfish;
extern crate byteorder;
extern crate clear_on_drop;
extern crate sha2;

use byteorder::{BigEndian, ByteOrder};
use clear_on_drop::clear::Clear;
use sha2::{Digest, Sha512};
use bcrypt_hash::bcrypt_hash;

/// The `bcrypt_pbkdf` password hashing algorithm. The length of the hashed password is implied by
/// the length of `hash_out`.
pub fn bcrypt_pbkdf(password: &[u8], salt: &[u8], rounds: usize, hash_out: &mut [u8]) {
    if password.is_empty() || salt.is_empty() || hash_out.is_empty() {
        panic!("`password`, `salt` and `hash_out` cannot be empty.");
    }
    if rounds < 1 {
        panic!("`rounds` parameter cannot be 0.");
    }
    if hash_out.len() > 1024 {
        panic!("Length og `hash_out` must be less than 1024.");
    }

    let key_len = hash_out.len();
    let mut hashed_password = [0u8; 64];
    hashed_password.copy_from_slice(&Sha512::digest(password));

    let n_blocks = (key_len + 31) / 32;

    for count in 1..n_blocks + 1 {
        let mut sha512 = Sha512::default();
        sha512.input(salt);

        let mut counter_buf = [0u8; 4];
        BigEndian::write_u32(&mut counter_buf, count as u32);
        sha512.input(&counter_buf);
        let mut hashed_salt = sha512.result();

        let mut bcrypt_hash_out = [0u8; 32];
        bcrypt_hash(&hashed_password, &hashed_salt, &mut bcrypt_hash_out);

        let mut step = bcrypt_hash_out;

        for _ in 1..rounds {
            let mut sha512 = Sha512::default();
            sha512.input(&step);
            hashed_salt = sha512.result();

            bcrypt_hash(&hashed_password, &hashed_salt, &mut step);

            for (idx, itm) in bcrypt_hash_out.iter_mut().enumerate() {
                *itm ^= step[idx];

                let idx_ext = idx * n_blocks + count - 1;
                if idx_ext < key_len {
                    hash_out[idx_ext] = *itm;
                }
            }
        }

        step.clear();
        bcrypt_hash_out.clear();
    }

    hashed_password.clear();
}

#[test]
fn bcrypt_pbkdf_res() {
    let password = "password".as_bytes();
    let salt = "salt".as_bytes();
    let rounds = 4;
    let out_expected = [
        0x5b, 0xbf, 0x0c, 0xc2, 0x93, 0x58, 0x7f, 0x1c, 0x36, 0x35, 0x55, 0x5c, 0x27, 0x79, 0x65,
        0x98, 0xd4, 0x7e, 0x57, 0x90, 0x71, 0xbf, 0x42, 0x7e, 0x9d, 0x8f, 0xbe, 0x84, 0x2a, 0xba,
        0x34, 0xd9,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_2() {
    let password = "password".as_bytes();
    let salt = [0x00];
    let rounds = 4;
    let out_expected = [
        0xc1, 0x2b, 0x56, 0x62, 0x35, 0xee, 0xe0, 0x4c, 0x21, 0x25, 0x98, 0x97, 0x0a, 0x57, 0x9a,
        0x67,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(&password, &salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_3() {
    let password = [0x00];
    let salt = "salt".as_bytes();
    let rounds = 4;
    let out_expected = [
        0x60, 0x51, 0xbe, 0x18, 0xc2, 0xf4, 0xf8, 0x2c, 0xbf, 0x0e, 0xfe, 0xe5, 0x47, 0x1b, 0x4b,
        0xb9,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(&password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_4() {
    let password = "password\x00".as_bytes();
    let salt = "salt\x00".as_bytes();
    let rounds = 4;
    let out_expected = [
        0x74, 0x10, 0xe4, 0x4c, 0xf4, 0xfa, 0x07, 0xbf, 0xaa, 0xc8, 0xa9, 0x28, 0xb1, 0x72, 0x7f,
        0xac, 0x00, 0x13, 0x75, 0xe7, 0xbf, 0x73, 0x84, 0x37, 0x0f, 0x48, 0xef, 0xd1, 0x21, 0x74,
        0x30, 0x50,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_5() {
    let password = "pass\x00wor".as_bytes();
    let salt = "sa\x00l".as_bytes();
    let rounds = 4;
    let out_expected = [
        0xc2, 0xbf, 0xfd, 0x9d, 0xb3, 0x8f, 0x65, 0x69, 0xef, 0xef, 0x43, 0x72, 0xf4, 0xde, 0x83,
        0xc0,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_6() {
    let password = "pass\x00wor".as_bytes();
    let salt = "sa\x00l".as_bytes();
    let rounds = 4;
    let out_expected = [
        0xc2, 0xbf, 0xfd, 0x9d, 0xb3, 0x8f, 0x65, 0x69, 0xef, 0xef, 0x43, 0x72, 0xf4, 0xde, 0x83,
        0xc0,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_7() {
    let password = "pass\x00word".as_bytes();
    let salt = "sa\x00lt".as_bytes();
    let rounds = 4;
    let out_expected = [
        0x4b, 0xa4, 0xac, 0x39, 0x25, 0xc0, 0xe8, 0xd7, 0xf0, 0xcd, 0xb6, 0xbb, 0x16, 0x84, 0xa5,
        0x6f,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_8() {
    let password = "password".as_bytes();
    let salt = "salt".as_bytes();
    let rounds = 8;
    let out_expected = [
        0xe1, 0x36, 0x7e, 0xc5, 0x15, 0x1a, 0x33, 0xfa, 0xac, 0x4c, 0xc1, 0xc1, 0x44, 0xcd, 0x23,
        0xfa, 0x15, 0xd5, 0x54, 0x84, 0x93, 0xec, 0xc9, 0x9b, 0x9b, 0x5d, 0x9c, 0x0d, 0x3b, 0x27,
        0xbe, 0xc7, 0x62, 0x27, 0xea, 0x66, 0x08, 0x8b, 0x84, 0x9b, 0x20, 0xab, 0x7a, 0xa4, 0x78,
        0x01, 0x02, 0x46, 0xe7, 0x4b, 0xba, 0x51, 0x72, 0x3f, 0xef, 0xa9, 0xf9, 0x47, 0x4d, 0x65,
        0x08, 0x84, 0x5e, 0x8d,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_9() {
    let password = "password".as_bytes();
    let salt = "salt".as_bytes();
    let rounds = 42;
    let out_expected = [
        0x83, 0x3c, 0xf0, 0xdc, 0xf5, 0x6d, 0xb6, 0x56, 0x08, 0xe8, 0xf0, 0xdc, 0x0c, 0xe8, 0x82,
        0xbd,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_10() {
    let password = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.".as_bytes();
    let salt = "salis\x00".as_bytes();
    let rounds = 8;
    let out_expected = [
        0x10, 0x97, 0x8b, 0x07, 0x25, 0x3d, 0xf5, 0x7f, 0x71, 0xa1, 0x62, 0xeb, 0x0e, 0x8a, 0xd3,
        0x0a,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_11() {
    let mut password = std::vec::Vec::new();
    password.extend_from_slice(&[
        0x0d, 0xb3, 0xac, 0x94, 0xb3, 0xee, 0x53, 0x28, 0x4f, 0x4a, 0x22, 0x89, 0x3b, 0x3c, 0x24,
        0xae,
    ]);

    let mut salt = std::vec::Vec::new();
    salt.extend_from_slice(&[
        0x3a, 0x62, 0xf0, 0xf0, 0xdb, 0xce, 0xf8, 0x23, 0xcf, 0xcc, 0x85, 0x48, 0x56, 0xea, 0x10,
        0x28,
    ]);
    let rounds = 8;
    let out_expected = [
        0x20, 0x44, 0x38, 0x17, 0x5e, 0xee, 0x7c, 0xe1, 0x36, 0xc9, 0x1b, 0x49, 0xa6, 0x79, 0x23,
        0xff,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(&password, &salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
fn bcrypt_pbkdf_res_12() {
    let mut password = std::vec::Vec::new();
    password.extend_from_slice(&[
        0x0d, 0xb3, 0xac, 0x94, 0xb3, 0xee, 0x53, 0x28, 0x4f, 0x4a, 0x22, 0x89, 0x3b, 0x3c, 0x24,
        0xae,
    ]);

    let mut salt = std::vec::Vec::new();
    salt.extend_from_slice(&[
        0x3a, 0x62, 0xf0, 0xf0, 0xdb, 0xce, 0xf8, 0x23, 0xcf, 0xcc, 0x85, 0x48, 0x56, 0xea, 0x10,
        0x28,
    ]);
    let rounds = 8;
    let out_expected = [
        0x20, 0x54, 0xb9, 0xff, 0xf3, 0x4e, 0x37, 0x21, 0x44, 0x03, 0x34, 0x74, 0x68, 0x28, 0xe9,
        0xed, 0x38, 0xde, 0x4b, 0x72, 0xe0, 0xa6, 0x9a, 0xdc, 0x17, 0x0a, 0x13, 0xb5, 0xe8, 0xd6,
        0x46, 0x38, 0x5e, 0xa4, 0x03, 0x4a, 0xe6, 0xd2, 0x66, 0x00, 0xee, 0x23, 0x32, 0xc5, 0xed,
        0x40, 0xad, 0x55, 0x7c, 0x86, 0xe3, 0x40, 0x3f, 0xbb, 0x30, 0xe4, 0xe1, 0xdc, 0x1a, 0xe0,
        0x6b, 0x99, 0xa0, 0x71, 0x36, 0x8f, 0x51, 0x8d, 0x2c, 0x42, 0x66, 0x51, 0xc9, 0xe7, 0xe4,
        0x37, 0xfd, 0x6c, 0x91, 0x5b, 0x1b, 0xbf, 0xc3, 0xa4, 0xce, 0xa7, 0x14, 0x91, 0x49, 0x0e,
        0xa7, 0xaf, 0xb7, 0xdd, 0x02, 0x90, 0xa6, 0x78, 0xa4, 0xf4, 0x41, 0x12, 0x8d, 0xb1, 0x79,
        0x2e, 0xab, 0x27, 0x76, 0xb2, 0x1e, 0xb4, 0x23, 0x8e, 0x07, 0x15, 0xad, 0xd4, 0x12, 0x7d,
        0xff, 0x44, 0xe4, 0xb3, 0xe4, 0xcc, 0x4c, 0x4f, 0x99, 0x70, 0x08, 0x3f, 0x3f, 0x74, 0xbd,
        0x69, 0x88, 0x73, 0xfd, 0xf6, 0x48, 0x84, 0x4f, 0x75, 0xc9, 0xbf, 0x7f, 0x9e, 0x0c, 0x4d,
        0x9e, 0x5d, 0x89, 0xa7, 0x78, 0x39, 0x97, 0x49, 0x29, 0x66, 0x61, 0x67, 0x07, 0x61, 0x1c,
        0xb9, 0x01, 0xde, 0x31, 0xa1, 0x97, 0x26, 0xb6, 0xe0, 0x8c, 0x3a, 0x80, 0x01, 0x66, 0x1f,
        0x2d, 0x5c, 0x9d, 0xcc, 0x33, 0xb4, 0xaa, 0x07, 0x2f, 0x90, 0xdd, 0x0b, 0x3f, 0x54, 0x8d,
        0x5e, 0xeb, 0xa4, 0x21, 0x13, 0x97, 0xe2, 0xfb, 0x06, 0x2e, 0x52, 0x6e, 0x1d, 0x68, 0xf4,
        0x6a, 0x4c, 0xe2, 0x56, 0x18, 0x5b, 0x4b, 0xad, 0xc2, 0x68, 0x5f, 0xbe, 0x78, 0xe1, 0xc7,
        0x65, 0x7b, 0x59, 0xf8, 0x3a, 0xb9, 0xab, 0x80, 0xcf, 0x93, 0x18, 0xd6, 0xad, 0xd1, 0xf5,
        0x93, 0x3f, 0x12, 0xd6, 0xf3, 0x61, 0x82, 0xc8, 0xe8, 0x11, 0x5f, 0x68, 0x03, 0x0a, 0x12,
        0x44,
    ];
    let mut out_actual = vec![0u8; out_expected.len()];
    bcrypt_pbkdf(&password, &salt, rounds, &mut out_actual);

    assert_eq!(out_actual, out_expected.as_ref());
}

#[test]
#[should_panic]
fn password_len_panic() {
    let password = "".as_bytes();
    let salt = "salt".as_bytes();
    let rounds = 42;
    let out_expected = [
        0x83, 0x3c, 0xf0, 0xdc, 0xf5, 0x6d, 0xb6, 0x56, 0x08, 0xe8, 0xf0, 0xdc, 0x0c, 0xe8, 0x82,
        0xbd,
    ];
    let mut out_actual = [0u8; 16];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual.as_ref(), out_expected.as_ref());
}

#[test]
#[should_panic]
fn salt_len_panic() {
    let password = "password".as_bytes();
    let salt = "".as_bytes();
    let rounds = 42;
    let out_expected = [
        0x83, 0x3c, 0xf0, 0xdc, 0xf5, 0x6d, 0xb6, 0x56, 0x08, 0xe8, 0xf0, 0xdc, 0x0c, 0xe8, 0x82,
        0xbd,
    ];
    let mut out_actual = [0u8; 16];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual.as_ref(), out_expected.as_ref());
}

#[test]
#[should_panic]
fn hash_out_len_small_panic() {
    let password = "password".as_bytes();
    let salt = "salt".as_bytes();
    let rounds = 42;
    let out_expected = [
        0x83, 0x3c, 0xf0, 0xdc, 0xf5, 0x6d, 0xb6, 0x56, 0x08, 0xe8, 0xf0, 0xdc, 0x0c, 0xe8, 0x82,
        0xbd,
    ];
    let mut out_actual = [0u8; 0];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual.as_ref(), out_expected.as_ref());
}

#[test]
#[should_panic]
fn hash_out_len_high_panic() {
    let password = "password".as_bytes();
    let salt = "salt".as_bytes();
    let rounds = 42;
    let out_expected = [
        0x83, 0x3c, 0xf0, 0xdc, 0xf5, 0x6d, 0xb6, 0x56, 0x08, 0xe8, 0xf0, 0xdc, 0x0c, 0xe8, 0x82,
        0xbd,
    ];
    let mut out_actual = [0u8; 1025];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual.as_ref(), out_expected.as_ref());
}

#[test]
#[should_panic]
fn zero_rounds_panic() {
    let password = "password".as_bytes();
    let salt = "salt".as_bytes();
    let rounds = 0;
    let out_expected = [
        0x83, 0x3c, 0xf0, 0xdc, 0xf5, 0x6d, 0xb6, 0x56, 0x08, 0xe8, 0xf0, 0xdc, 0x0c, 0xe8, 0x82,
        0xbd,
    ];
    let mut out_actual = [0u8; 16];
    bcrypt_pbkdf(password, salt, rounds, &mut out_actual);

    assert_eq!(out_actual.as_ref(), out_expected.as_ref());
}
