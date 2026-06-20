//! Time-based one-time passwords (RFC 6238 / RFC 4226).
//!
//! SHA-1, 6 digits, 30-second period — the de-facto default that authenticator
//! apps emit. The current time is passed in (unix seconds) so the function is
//! pure and testable against the RFC vectors.
//!
//! TODO(phase-2): support configurable digits/period and SHA-256/512 once we
//! parse `otpauth://` URIs on import.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

const PERIOD_SECS: u64 = 30;
const DIGITS: u32 = 6;

/// A generated TOTP plus the timing needed to render a countdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    /// Zero-padded numeric code, e.g. `"287082"`.
    pub code: String,
    /// Step length in seconds (30).
    pub period: u64,
    /// Seconds remaining until this code rolls over (1..=period).
    pub remaining: u64,
}

/// Compute the current TOTP for a Base32 secret at `unix_seconds`.
pub fn current_totp(base32_secret: &str, unix_seconds: u64) -> Result<TotpCode> {
    let secret = decode_base32_secret(base32_secret)?;
    let counter = unix_seconds / PERIOD_SECS;
    let code = hotp(&secret, counter, DIGITS)?;
    let remaining = PERIOD_SECS - (unix_seconds % PERIOD_SECS);
    Ok(TotpCode {
        code,
        period: PERIOD_SECS,
        remaining,
    })
}

/// Normalize and Base32-decode a TOTP shared secret. Tolerates lowercase,
/// spaces, and `=` padding (as copied from various providers).
fn decode_base32_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .flat_map(char::to_uppercase)
        .collect();
    let bytes = data_encoding::BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| Error::InvalidTotpSecret)?;
    Ok(Zeroizing::new(bytes))
}

/// RFC 4226 HOTP with dynamic truncation.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| Error::InvalidTotpSecret)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);

    let modulus = 10u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        bin % modulus,
        width = digits as usize
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test seed: ASCII "12345678901234567890".
    const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors_truncated_to_6_digits() {
        // RFC 6238 lists 8-digit values; the low 6 digits must match.
        // T=59  -> 94287082 -> "287082"
        assert_eq!(current_totp(RFC_SECRET_B32, 59).unwrap().code, "287082");
        // T=1111111109 -> 07081804 -> "081804"
        assert_eq!(
            current_totp(RFC_SECRET_B32, 1_111_111_109).unwrap().code,
            "081804"
        );
    }

    #[test]
    fn remaining_counts_down_within_period() {
        assert_eq!(current_totp(RFC_SECRET_B32, 0).unwrap().remaining, 30);
        assert_eq!(current_totp(RFC_SECRET_B32, 1).unwrap().remaining, 29);
        assert_eq!(current_totp(RFC_SECRET_B32, 29).unwrap().remaining, 1);
        assert_eq!(current_totp(RFC_SECRET_B32, 30).unwrap().remaining, 30);
    }

    #[test]
    fn tolerates_lowercase_spaces_and_padding() {
        let messy = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(current_totp(messy, 59).unwrap().code, "287082");
    }

    #[test]
    fn rejects_invalid_base32() {
        assert!(matches!(
            current_totp("not valid base32 !!!", 0),
            Err(Error::InvalidTotpSecret)
        ));
    }
}
