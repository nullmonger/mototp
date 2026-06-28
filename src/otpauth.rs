// Parse an otpauth:// URI (Key Uri Format) into an Entry.
// No binary callers, so the allow silences dead-code lints.
#![allow(dead_code)]

use percent_encoding::percent_decode_str;

use crate::entry::{Entry, OtpKind};
use crate::otp::{Algorithm, decode_secret, validate_digits};

// Error messages are static and never include secret material.
// FIXME: MalformedSecret, UnsupportedDigits and ZeroPeriod duplicate OtpError's
// variants and messages; wrapping OtpError would avoid the message drift.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("not an otpauth:// URI")]
    NotOtpauth,
    #[error("unknown OTP type")]
    UnknownType,
    #[error("secret is missing")]
    MissingSecret,
    #[error("secret is not valid base32")]
    MalformedSecret,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("code length must be 6 to 8 digits")]
    UnsupportedDigits,
    #[error("TOTP period must be greater than zero")]
    ZeroPeriod,
    #[error("numeric parameter is not a number")]
    InvalidNumber,
    #[error("HOTP requires a counter")]
    MissingCounter,
}

enum OtpType {
    Totp,
    Hotp,
}

pub fn parse(uri: &str) -> Result<Entry, ParseError> {
    let (scheme, rest) = uri.split_once("://").ok_or(ParseError::NotOtpauth)?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err(ParseError::NotOtpauth);
    }

    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (type_str, label_raw) = path.split_once('/').unwrap_or((path, ""));

    // Reject an unknown type up front, before parameter errors can mask it.
    let otp_type = if type_str.eq_ignore_ascii_case("totp") {
        OtpType::Totp
    } else if type_str.eq_ignore_ascii_case("hotp") {
        OtpType::Hotp
    } else {
        return Err(ParseError::UnknownType);
    };

    let params = QueryParams::parse(query);

    let secret_str = params.get("secret").ok_or(ParseError::MissingSecret)?;
    let secret = decode_secret(&secret_str).map_err(|_| ParseError::MalformedSecret)?;

    let algorithm = match params.get("algorithm") {
        None => Algorithm::Sha1,
        Some(a) if a.eq_ignore_ascii_case("SHA1") => Algorithm::Sha1,
        Some(a) if a.eq_ignore_ascii_case("SHA256") => Algorithm::Sha256,
        Some(a) if a.eq_ignore_ascii_case("SHA512") => Algorithm::Sha512,
        Some(_) => return Err(ParseError::UnsupportedAlgorithm),
    };

    let digits = match params.get("digits") {
        None => 6,
        Some(d) => d.parse::<u32>().map_err(|_| ParseError::InvalidNumber)?,
    };
    validate_digits(digits).map_err(|_| ParseError::UnsupportedDigits)?;

    // The colon and the spaces after it may arrive percent-encoded,
    // so decode the whole label before splitting "issuer:account".
    let label = percent_decode(label_raw);
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.to_string()), account.trim().to_string()),
        None => (None, label.trim().to_string()),
    };
    // The issuer parameter wins over the label prefix when both are present.
    let issuer = non_empty(params.get("issuer")).or(non_empty(label_issuer));

    let kind = match otp_type {
        OtpType::Totp => {
            let period = match params.get("period") {
                None => 30,
                Some(p) => p.parse::<u64>().map_err(|_| ParseError::InvalidNumber)?,
            };
            if period == 0 {
                return Err(ParseError::ZeroPeriod);
            }
            OtpKind::Totp { period }
        }
        OtpType::Hotp => {
            let counter_str = params.get("counter").ok_or(ParseError::MissingCounter)?;
            let counter = counter_str
                .parse::<u64>()
                .map_err(|_| ParseError::InvalidNumber)?;
            OtpKind::Hotp { counter }
        }
    };

    Ok(Entry {
        issuer,
        label: account,
        secret,
        algorithm,
        digits,
        kind,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct LineError {
    pub line: usize,
    pub error: ParseError,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParseReport {
    pub entries: Vec<Entry>,
    pub errors: Vec<LineError>,
}

// Accumulate per-line errors instead of failing on the first bad line,
// so one broken line does not drop the rest of an import.
pub fn parse_list(input: &str) -> ParseReport {
    let mut report = ParseReport::default();
    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse(line) {
            Ok(entry) => report.entries.push(entry),
            Err(error) => report.errors.push(LineError {
                line: index + 1,
                error,
            }),
        }
    }
    report
}

// Percent-decoded query parameters. First occurrence of a key wins.
struct QueryParams(Vec<(String, String)>);

impl QueryParams {
    fn parse(query: &str) -> Self {
        let pairs = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (
                    percent_decode(key).to_ascii_lowercase(),
                    percent_decode(value),
                )
            })
            .collect();
        Self(pairs)
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}

fn percent_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

// Normalize both issuer sources the same way: trim, drop if empty.
fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC secret "12345678901234567890" as base32.
    const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn parses_canonical_totp() {
        let uri = format!(
            "otpauth://totp/Example:alice@google.com\
             ?secret={SECRET_B32}&issuer=Example&algorithm=SHA1&digits=8&period=30"
        );
        let entry = parse(&uri).unwrap();
        assert_eq!(entry.issuer.as_deref(), Some("Example"));
        assert_eq!(entry.label, "alice@google.com");
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 8);
        assert_eq!(entry.kind, OtpKind::Totp { period: 30 });
    }

    #[test]
    fn parses_canonical_hotp() {
        let uri = format!("otpauth://hotp/alice?secret={SECRET_B32}&counter=5");
        let entry = parse(&uri).unwrap();
        assert_eq!(entry.kind, OtpKind::Hotp { counter: 5 });
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
    }

    #[test]
    fn issuer_from_prefix_and_param_agree() {
        let from_prefix = parse(&format!(
            "otpauth://totp/Example:alice?secret={SECRET_B32}&issuer=Example"
        ))
        .unwrap();
        let from_param = parse(&format!(
            "otpauth://totp/alice?secret={SECRET_B32}&issuer=Example"
        ))
        .unwrap();
        assert_eq!(from_prefix, from_param);
        assert_eq!(from_prefix.issuer.as_deref(), Some("Example"));
        assert_eq!(from_prefix.label, "alice");
    }

    // On disagreement the parameter wins, deterministically.
    #[test]
    fn issuer_param_wins_on_mismatch() {
        let entry = parse(&format!(
            "otpauth://totp/Label:alice?secret={SECRET_B32}&issuer=Param"
        ))
        .unwrap();
        assert_eq!(entry.issuer.as_deref(), Some("Param"));
        assert_eq!(entry.label, "alice");
    }

    #[test]
    fn applies_defaults() {
        let entry = parse(&format!("otpauth://totp/alice?secret={SECRET_B32}")).unwrap();
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.kind, OtpKind::Totp { period: 30 });
    }

    // Label is optional: an issuer-only URI parses with an empty account.
    #[test]
    fn accepts_empty_account() {
        let entry = parse(&format!(
            "otpauth://totp/?secret={SECRET_B32}&issuer=Example"
        ))
        .unwrap();
        assert_eq!(entry.issuer.as_deref(), Some("Example"));
        assert_eq!(entry.label, "");
    }

    // RFC 6238 Appendix B: t=59, 8 digits -> 94287082.
    #[test]
    fn parsed_totp_matches_rfc_vector() {
        let uri =
            format!("otpauth://totp/alice?secret={SECRET_B32}&algorithm=SHA1&digits=8&period=30");
        let entry = parse(&uri).unwrap();
        assert_eq!(entry.code_at(59).unwrap(), "94287082");
    }

    // RFC 4226 Appendix D: counter 0 -> 755224.
    #[test]
    fn parsed_hotp_matches_rfc_vector() {
        let entry = parse(&format!(
            "otpauth://hotp/alice?secret={SECRET_B32}&counter=0"
        ))
        .unwrap();
        assert_eq!(entry.code_at(0).unwrap(), "755224");
    }

    #[test]
    fn rejects_invalid_uris_with_distinct_causes() {
        let valid = format!("secret={SECRET_B32}");
        let cases = vec![
            ("https://example.com".to_string(), ParseError::NotOtpauth),
            ("otpauth://weird/a".to_string(), ParseError::UnknownType),
            ("otpauth://totp/a".to_string(), ParseError::MissingSecret),
            (
                "otpauth://totp/a?secret=@@@".to_string(),
                ParseError::MalformedSecret,
            ),
            (
                format!("otpauth://hotp/a?{valid}"),
                ParseError::MissingCounter,
            ),
            (
                format!("otpauth://totp/a?{valid}&digits=abc"),
                ParseError::InvalidNumber,
            ),
            (
                format!("otpauth://totp/a?{valid}&digits=9"),
                ParseError::UnsupportedDigits,
            ),
            (
                format!("otpauth://totp/a?{valid}&algorithm=md5"),
                ParseError::UnsupportedAlgorithm,
            ),
            (
                format!("otpauth://totp/a?{valid}&period=0"),
                ParseError::ZeroPeriod,
            ),
        ];
        for (uri, expected) in cases {
            assert_eq!(parse(&uri).unwrap_err(), expected, "case {expected:?}");
        }
    }

    #[test]
    fn parse_list_collects_entries_and_errors() {
        let input = format!(
            "otpauth://totp/a?secret={SECRET_B32}\n\
             not-a-uri\n\
             \n\
             otpauth://hotp/b?secret={SECRET_B32}&counter=0\n\
             otpauth://totp/c?secret=@@@\n"
        );
        let report = parse_list(&input);

        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.errors.len(), 2);
        // Line numbers are 1-based and count the skipped blank line.
        assert_eq!(report.errors[0].line, 2);
        assert_eq!(report.errors[0].error, ParseError::NotOtpauth);
        assert_eq!(report.errors[1].line, 5);
        assert_eq!(report.errors[1].error, ParseError::MalformedSecret);
    }
}
