// Authenticator entry: a secret and the OTP parameters to compute its code.
// No binary callers, so the allow silences dead-code lints.
#![allow(dead_code)]

use std::fmt;

use crate::otp::{Algorithm, OtpError, OtpParams, hotp, totp_at, validate_digits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpKind {
    Totp { period: u64 },
    Hotp { counter: u64 },
}

#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    pub issuer: Option<String>,
    pub label: String,
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub kind: OtpKind,
}

// Custom Debug redacts the secret so it never reaches logs.
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("issuer", &self.issuer)
            .field("label", &self.label)
            .field(
                "secret",
                &format_args!("<redacted; {} bytes>", self.secret.len()),
            )
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .finish()
    }
}

impl Entry {
    // TOTP needs the time; HOTP ignores it and uses its stored counter.
    pub fn code_at(&self, unix_time: u64) -> Result<String, OtpError> {
        match self.kind {
            OtpKind::Totp { period } => {
                let params = OtpParams {
                    algorithm: self.algorithm,
                    digits: self.digits,
                    period,
                    t0: 0,
                };
                Ok(totp_at(&params, &self.secret, unix_time)?.code)
            }
            OtpKind::Hotp { counter } => {
                // hotp does not guard the digit range, so check before calling.
                validate_digits(self.digits)?;
                Ok(hotp(self.algorithm, &self.secret, counter, self.digits))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B: SHA-1 secret, period 30, 8 digits, t=59 -> 94287082.
    #[test]
    fn totp_entry_matches_rfc_vector() {
        let entry = Entry {
            issuer: Some("Example".into()),
            label: "alice".into(),
            secret: b"12345678901234567890".to_vec(),
            algorithm: Algorithm::Sha1,
            digits: 8,
            kind: OtpKind::Totp { period: 30 },
        };
        assert_eq!(entry.code_at(59).unwrap(), "94287082");
    }

    // RFC 4226 Appendix D: counter 0 -> 755224, counter 1 -> 287082 (6 digits).
    #[test]
    fn hotp_entry_matches_rfc_vector() {
        let entry = |counter| Entry {
            issuer: None,
            label: "alice".into(),
            secret: b"12345678901234567890".to_vec(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: OtpKind::Hotp { counter },
        };
        assert_eq!(entry(0).code_at(0).unwrap(), "755224");
        assert_eq!(entry(1).code_at(0).unwrap(), "287082");
    }

    // Digits outside 6..=8 must error, not panic in the core's truncation.
    #[test]
    fn hotp_entry_rejects_invalid_digits() {
        let entry = Entry {
            issuer: None,
            label: "alice".into(),
            secret: b"12345678901234567890".to_vec(),
            algorithm: Algorithm::Sha1,
            digits: 9,
            kind: OtpKind::Hotp { counter: 0 },
        };
        assert_eq!(entry.code_at(0), Err(OtpError::UnsupportedDigits));
    }
}
