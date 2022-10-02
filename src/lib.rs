//! Small `no-std` implementation of the TOTP algorithm.
//!
//! Only SHA-1 is supported.
//!
//! ```
//! use std::time::SystemTime;
//!
//! let secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
//! let _ = nyx::generate("12345678901234567890", secs);
//! ```
//!
//! Based on the implementation from [totp-rs](https://crates.io/crates/totp-rs).

#![no_std]

use core::convert::TryInto;
use hmac::digest::Output;
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// This will generate 6 digits codes, with a skew of 1 and step size of 30.
const TOTP: Totp = Totp::options(6, 1, 30);

/// Function for generating TOTP tokens.
///
/// This will generate 6 digits codes with step size of 30.
///
/// ```
/// assert_eq!(nyx::generate("12345678901234567890", 59), 287082);
/// ```
pub fn generate(key: impl AsRef<[u8]>, secs: u64) -> u32 {
    TOTP.generate(key.as_ref(), secs)
}

/// Function for verifying TOTP tokens.
///
/// This will expect a 6 digits token, and use a skew of 1 and step size of 30.
///
/// ```
/// assert!(nyx::verify("12345678901234567890", 59, 287082));
/// ```
pub fn verify(key: impl AsRef<[u8]>, secs: u64, token: u32) -> bool {
    TOTP.verify(key.as_ref(), secs, token)
}

/// The TOTP token generator.
#[derive(Copy, Clone, Debug)]
struct Totp {
    digits: u32,
    skew: u8,
    step: u64,
}

impl Totp {
    /// Returns a new `TOTP` struct with the provided options.
    const fn options(digits: u32, skew: u8, step: u64) -> Totp {
        Totp { digits, skew, step }
    }

    /// Sign using `SHA1`.
    fn sign(&self, key: &[u8], secs: u64) -> Output<Hmac<Sha1>> {
        let msg = (secs / self.step).to_be_bytes();
        let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
        mac.update(&msg);
        mac.finalize().into_bytes()
    }

    /// Generates the `TOTP` value.
    fn generate(&self, key: &[u8], secs: u64) -> u32 {
        let signed = self.sign(key, secs);
        let offset = (signed[19] & 0xf) as usize;
        let buf = &signed[offset..offset + 4];
        let buf: [u8; 4] = buf.try_into().unwrap();
        let binary = u32::from_be_bytes(buf) & 0x7fff_ffff;
        binary % 10_u32.pow(self.digits)
    }

    /// Checks if the given token matches the provided key and time.
    fn verify(&self, key: &[u8], secs: u64, token: u32) -> bool {
        let offset = secs / self.step - self.skew as u64;
        for i in 0..self.skew * 2 + 1 {
            let secs = (offset + i as u64) * self.step;
            if self.generate(key, secs) == token {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Totp;

    #[test]
    fn totp_8_digits_0_skew_30_step() {
        // Test values from https://tools.ietf.org/html/rfc6238.
        const TOTP: Totp = Totp::options(8, 0, 30);
        assert!(TOTP.verify(b"12345678901234567890", 59, 94287082));
        assert!(TOTP.verify(b"12345678901234567890", 1111111109, 7081804));
        assert!(TOTP.verify(b"12345678901234567890", 1111111111, 14050471));
        assert!(TOTP.verify(b"12345678901234567890", 1234567890, 89005924));
        assert!(TOTP.verify(b"12345678901234567890", 2000000000, 69279037));
        assert!(TOTP.verify(b"12345678901234567890", 20000000000, 65353130));
    }
}
