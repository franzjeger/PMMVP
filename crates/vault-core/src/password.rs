//! Cryptographically-secure password generation.
//!
//! Indices are drawn from the OS CSPRNG with rejection sampling, so there is
//! no modulo bias. When length permits, at least one character from each
//! selected class is guaranteed, then the result is shuffled.

use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::error::{Error, Result};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Avoids ambiguous/quoting-hostile characters while staying strong.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

/// Which character classes to include and how long the password should be.
#[derive(Clone, Copy, Debug)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

impl PasswordOptions {
    fn classes(&self) -> Vec<&'static [u8]> {
        let mut v = Vec::with_capacity(4);
        if self.lowercase {
            v.push(LOWER);
        }
        if self.uppercase {
            v.push(UPPER);
        }
        if self.digits {
            v.push(DIGITS);
        }
        if self.symbols {
            v.push(SYMBOLS);
        }
        v
    }
}

/// Generate a password per `opts`. The result is held in a zeroizing buffer so
/// it is wiped when dropped; copy it out only when handing to the caller.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    if opts.length == 0 {
        return Err(Error::InvalidArgument("password length must be > 0"));
    }
    let classes = opts.classes();
    if classes.is_empty() {
        return Err(Error::InvalidArgument(
            "at least one character class required",
        ));
    }

    let alphabet: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();

    let mut chars: Vec<u8> = Vec::with_capacity(opts.length);

    // Guarantee class coverage when there is room for it.
    if opts.length >= classes.len() {
        for class in &classes {
            chars.push(class[random_below(class.len())?]);
        }
    }
    while chars.len() < opts.length {
        chars.push(alphabet[random_below(alphabet.len())?]);
    }

    shuffle(&mut chars)?;

    // `chars` is ASCII by construction, so this is valid UTF-8.
    let password = String::from_utf8(chars).expect("alphabet is ASCII");
    Ok(Zeroizing::new(password))
}

/// Uniform random index in `0..n` via rejection sampling (no modulo bias).
fn random_below(n: usize) -> Result<usize> {
    debug_assert!(n > 0);
    let range = n as u64;
    let span = 1u64 << 32; // 2^32 outcomes from a u32 draw
    let zone = span - (span % range); // largest multiple of `range` below 2^32
    loop {
        let mut buf = [0u8; 4];
        fill_random(&mut buf)?;
        let x = u32::from_le_bytes(buf) as u64;
        if x < zone {
            return Ok((x % range) as usize);
        }
    }
}

/// In-place Fisher-Yates shuffle using the CSPRNG.
fn shuffle(items: &mut [u8]) -> Result<()> {
    for i in (1..items.len()).rev() {
        let j = random_below(i + 1)?;
        items.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length() {
        let opts = PasswordOptions {
            length: 32,
            ..Default::default()
        };
        assert_eq!(generate_password(&opts).unwrap().len(), 32);
    }

    #[test]
    fn includes_each_selected_class() {
        let opts = PasswordOptions {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        };
        // Run several times since coverage is probabilistic per draw but
        // guaranteed by construction.
        for _ in 0..50 {
            let pw = generate_password(&opts).unwrap();
            assert!(pw.bytes().any(|b| LOWER.contains(&b)));
            assert!(pw.bytes().any(|b| UPPER.contains(&b)));
            assert!(pw.bytes().any(|b| DIGITS.contains(&b)));
            assert!(pw.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }

    #[test]
    fn only_uses_selected_classes() {
        let opts = PasswordOptions {
            length: 40,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        let pw = generate_password(&opts).unwrap();
        assert!(pw.bytes().all(|b| DIGITS.contains(&b)));
    }

    #[test]
    fn rejects_empty_class_set_and_zero_length() {
        let no_classes = PasswordOptions {
            length: 10,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
        };
        assert!(generate_password(&no_classes).is_err());

        let zero_len = PasswordOptions {
            length: 0,
            ..Default::default()
        };
        assert!(generate_password(&zero_len).is_err());
    }

    #[test]
    fn random_below_stays_in_range() {
        for n in 1..50usize {
            for _ in 0..20 {
                assert!(random_below(n).unwrap() < n);
            }
        }
    }
}
