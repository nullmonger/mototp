// OTP computation core: HOTP (RFC 4226) and TOTP (RFC 6238).
// No caller in the binary yet, so the allow silences dead-code lints.
// The module is exercised by the tests below.
#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtpParams {
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub t0: u64,
}

impl Default for OtpParams {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            t0: 0,
        }
    }
}

// Error messages are static and never include secret material.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OtpError {
    #[error("TOTP period must be greater than zero")]
    ZeroPeriod,
    #[error("code length must be 6 to 8 digits")]
    UnsupportedDigits,
    #[error("secret is not valid base32")]
    MalformedSecret,
    #[error("system clock is before the UNIX epoch")]
    ClockBeforeEpoch,
}

// HMAC dispatch over the supported hash families.
// A local macro avoids repeating the three arms and the verbose trait bounds.
fn hmac_digest(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    macro_rules! mac {
        ($hash:ty) => {{
            // HMAC takes a key of any length, so this never errors.
            let mut mac = Hmac::<$hash>::new_from_slice(key).unwrap();
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm {
        Algorithm::Sha1 => mac!(Sha1),
        Algorithm::Sha256 => mac!(Sha256),
        Algorithm::Sha512 => mac!(Sha512),
    }
}

// Dynamic truncation per RFC 4226 section 5.3.
// Callers pass a full HMAC digest (>= 20 bytes) and a digit count in 6..=8,
// so the indexing and the modulo below cannot panic or overflow.
fn truncate(mac: &[u8], digits: u32) -> String {
    debug_assert!(mac.len() >= 20, "truncate expects a full HMAC digest");
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    // High bit of the 31-bit slice is masked off to stay sign-agnostic.
    let bytes = [
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ];
    let binary = u64::from(u32::from_be_bytes(bytes));
    let code = binary % 10u64.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

pub fn hotp(algorithm: Algorithm, secret: &[u8], counter: u64, digits: u32) -> String {
    // Counter is the 8-byte big-endian moving factor (RFC 4226 section 5.1).
    let mac = hmac_digest(algorithm, secret, &counter.to_be_bytes());
    truncate(&mac, digits)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    // Seconds left until the code rolls over; UI progress reads this.
    pub remaining: u64,
}

pub fn totp_at(params: &OtpParams, secret: &[u8], unix_time: u64) -> Result<TotpCode, OtpError> {
    if params.period == 0 {
        return Err(OtpError::ZeroPeriod);
    }
    // Reject digits outside 6..=8: such values overflow the modulo
    // or produce a meaningless code.
    if !(6..=8).contains(&params.digits) {
        return Err(OtpError::UnsupportedDigits);
    }
    let elapsed = unix_time.saturating_sub(params.t0);
    let counter = elapsed / params.period;
    // At a window boundary the remainder is 0, so a full period is reported left.
    let remaining = params.period - (elapsed % params.period);
    let code = hotp(params.algorithm, secret, counter, params.digits);
    Ok(TotpCode { code, remaining })
}

pub fn totp_now(params: &OtpParams, secret: &[u8]) -> Result<TotpCode, OtpError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OtpError::ClockBeforeEpoch)?
        .as_secs();
    totp_at(params, secret, now)
}

// Decode an otpauth:// base32 secret (RFC 4648). Input is normalized first:
// whitespace is dropped (secrets are often shown in groups), case is folded up,
// and the optional padding is trimmed before decoding.
pub fn decode_secret(input: &str) -> Result<Vec<u8>, OtpError> {
    let normalized: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let normalized = normalized.to_uppercase();
    let trimmed = normalized.trim_end_matches('=');
    if trimmed.is_empty() {
        return Err(OtpError::MalformedSecret);
    }
    data_encoding::BASE32_NOPAD
        .decode(trimmed.as_bytes())
        .map_err(|_| OtpError::MalformedSecret)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D: secret "12345678901234567890", SHA-1, 6 digits.
    #[test]
    fn hotp_rfc4226_appendix_d() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                hotp(Algorithm::Sha1, secret, counter as u64, 6),
                *code,
                "HOTP mismatch at counter {counter}"
            );
        }
    }

    // RFC 6238 Appendix B: per-algorithm secrets (SHA-256/512 are not the same
    // 20-byte seed as SHA-1), period 30, T0 = 0, 8 digits.
    #[test]
    fn totp_rfc6238_appendix_b() {
        let sha1 = b"12345678901234567890".as_slice();
        let sha256 = b"12345678901234567890123456789012".as_slice();
        let sha512 = b"1234567890123456789012345678901234567890123456789012345678901234".as_slice();

        // (time, sha1, sha256, sha512)
        let vectors = [
            (59u64, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];

        for (time, c1, c256, c512) in vectors {
            let params = |algorithm| OtpParams {
                algorithm,
                digits: 8,
                period: 30,
                t0: 0,
            };
            assert_eq!(
                totp_at(&params(Algorithm::Sha1), sha1, time).unwrap().code,
                c1
            );
            assert_eq!(
                totp_at(&params(Algorithm::Sha256), sha256, time)
                    .unwrap()
                    .code,
                c256
            );
            assert_eq!(
                totp_at(&params(Algorithm::Sha512), sha512, time)
                    .unwrap()
                    .code,
                c512
            );
        }
    }

    // RFC 4648 base32 test vector: "MZXW6YTBOI" decodes to "foobar".
    #[test]
    fn decode_secret_base32() {
        assert_eq!(decode_secret("MZXW6YTBOI").unwrap(), b"foobar");
        // Spaces between groups are ignored.
        assert_eq!(decode_secret("MZXW 6YTB OI").unwrap(), b"foobar");
        // Lowercase is folded up.
        assert_eq!(decode_secret("mzxw6ytboi").unwrap(), b"foobar");
        assert_eq!(decode_secret(""), Err(OtpError::MalformedSecret));
        assert_eq!(decode_secret("1!@"), Err(OtpError::MalformedSecret));
    }

    #[test]
    fn totp_rejects_invalid_period_and_digits() {
        let zero_period = OtpParams {
            period: 0,
            ..OtpParams::default()
        };
        assert_eq!(
            totp_at(&zero_period, b"secret", 0),
            Err(OtpError::ZeroPeriod)
        );

        // digits outside 6..=8 are rejected rather than overflowing 10^digits.
        for digits in [0, 5, 9, 10] {
            let params = OtpParams {
                digits,
                ..OtpParams::default()
            };
            assert_eq!(
                totp_at(&params, b"secret", 0),
                Err(OtpError::UnsupportedDigits),
                "digits {digits} must be rejected"
            );
        }
    }

    #[test]
    fn totp_is_stable_within_a_window() {
        let secret = b"12345678901234567890";
        let params = OtpParams::default(); // period 30

        let start = totp_at(&params, secret, 30).unwrap();
        let end = totp_at(&params, secret, 59).unwrap();
        let next = totp_at(&params, secret, 60).unwrap();

        assert_eq!(
            start.code, end.code,
            "code must be stable inside one window"
        );
        assert_ne!(start.code, next.code, "code must change at the next window");

        // remaining counts down from a full period to 1 across the window.
        assert_eq!(start.remaining, 30);
        assert_eq!(end.remaining, 1);
    }

    #[test]
    fn code_length_matches_digits() {
        let secret = b"12345678901234567890";
        assert_eq!(hotp(Algorithm::Sha1, secret, 0, 6).len(), 6);
        let params = OtpParams {
            digits: 8,
            ..OtpParams::default()
        };
        assert_eq!(totp_at(&params, secret, 59).unwrap().code.len(), 8);
    }
}
