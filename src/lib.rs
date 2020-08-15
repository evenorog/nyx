//! Small `no-std` implementation of the TOTP algorithm.
//!
//! Only SHA-1 is supported.
//!
//! ```no_run
//! use std::time::SystemTime;
//!
//! let time = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
//! let _ = nyx::generate(b"12345678901234567890", time);
//! ```
//!
//! Thanks to [totp-rs](https://crates.io/crates/totp-rs) for providing the code this crate is based on.

#![no_std]

use byteorder::{BigEndian, ByteOrder};
use hmac::crypto_mac::Output;
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;

/// Convenience function for verifying TOTP tokens.
///
/// This will expect a 6 digits token, and use a skew of 1 and step size of 30.
///
/// ```
/// assert!(nyx::verify(b"12345678901234567890", 59, 287082));
/// ```
pub fn verify(key: &[u8], time: u64, token: u32) -> bool {
    Totp::new().verify(key, time, token)
}

/// Convenience function for generating TOTP tokens.
///
/// This will generate 6 digits codes with step size of 30.
///
/// ```
/// assert_eq!(nyx::generate(b"12345678901234567890", 59), 287082);
/// ```
pub fn generate(key: &[u8], time: u64) -> u32 {
    Totp::new().generate(key, time)
}

/// The TOTP token generator.
#[derive(Copy, Clone, Debug)]
pub struct Totp {
    digits: u32,
    skew: u8,
    step: u64,
}

impl Totp {
    /// Returns a new TOTP struct with default values.
    ///
    /// This will generate 6 digits codes, with a skew of 1 and step size of 30.
    ///
    /// This is equivalent to:
    /// ```
    /// # use nyx::Totp;
    /// Totp::options(6, 1, 30);
    /// ```
    pub const fn new() -> Totp {
        Totp::options(6, 1, 30)
    }

    /// Returns a new TOTP struct with the provided options.
    pub const fn options(digits: u32, skew: u8, step: u64) -> Totp {
        Totp { digits, skew, step }
    }

    fn sign(&self, key: &[u8], time: u64) -> Output<Hmac<Sha1>> {
        let ctr = (time / self.step).to_be_bytes();
        let mut mac = Hmac::<Sha1>::new_varkey(key).unwrap();
        mac.update(&ctr);
        mac.finalize()
    }

    /// Generates the TOTP value.
    pub fn generate(&self, key: &[u8], time: u64) -> u32 {
        let hash = &*self.sign(key, time).into_bytes();
        let offset = (hash[19] & 15) as usize;
        let buf = &hash[offset..offset + 4];
        let data = BigEndian::read_u32(buf) & 0x7fff_ffff;
        data % (10 as u32).pow(self.digits)
    }

    /// Checks if the given token matches the provided key and time.
    pub fn verify(&self, key: &[u8], time: u64, token: u32) -> bool {
        let offset = time / self.step - self.skew as u64;
        for i in 0..self.skew * 2 + 1 {
            let step_time = (offset + i as u64) * (self.step as u64);
            if self.generate(key, step_time) == token {
                return true;
            }
        }
        false
    }
}

impl Default for Totp {
    fn default() -> Self {
        Totp::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Totp;

    #[test]
    fn totp_8_digits() {
        // Test values from https://tools.ietf.org/html/rfc6238.
        const TOTP: Totp = Totp::options(8, 1, 30);
        assert!(TOTP.verify(b"12345678901234567890", 59, 94287082));
        assert!(TOTP.verify(b"12345678901234567890", 1111111109, 7081804));
        assert!(TOTP.verify(b"12345678901234567890", 1111111111, 14050471));
        assert!(TOTP.verify(b"12345678901234567890", 1234567890, 89005924));
        assert!(TOTP.verify(b"12345678901234567890", 2000000000, 69279037));
        assert!(TOTP.verify(b"12345678901234567890", 20000000000, 65353130));
    }
}
