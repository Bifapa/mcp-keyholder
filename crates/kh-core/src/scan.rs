//! Leak scanning: find full stored values (and common encodings) inside arbitrary text.
//! Only whole values match, so the scanner cannot be used to extract a value piece by piece.
//! Short and low-entropy values are excluded: for them a "does it match" oracle would be guessable.

use aho_corasick::AhoCorasick;
use data_encoding::{BASE64, BASE64URL_NOPAD, BASE64_NOPAD, HEXLOWER, HEXUPPER};

pub const MIN_LEN: usize = 16;
pub const MIN_BITS: f64 = 64.0;

/// Shannon entropy of the character distribution times the length, in bits.
pub fn entropy_bits(v: &str) -> f64 {
    let chars: Vec<char> = v.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0usize) += 1;
    }
    let n = chars.len() as f64;
    let per_char: f64 = counts.values().map(|&k| {
        let p = k as f64 / n;
        -p * p.log2()
    }).sum();
    per_char * n
}

pub fn eligible(v: &str) -> bool {
    v.chars().count() >= MIN_LEN && entropy_bits(v) >= MIN_BITS
}

fn url_encode(v: &str) -> String {
    let mut s = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// The forms of a value we look for.
pub fn variants(v: &str) -> Vec<String> {
    let b = v.as_bytes();
    let mut out = vec![
        v.to_string(),
        BASE64.encode(b),
        BASE64_NOPAD.encode(b),
        BASE64URL_NOPAD.encode(b),
        HEXLOWER.encode(b),
        HEXUPPER.encode(b),
        url_encode(v),
    ];
    if let Ok(j) = serde_json::to_string(v) {
        out.push(j.trim_matches('"').to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// `values`: (id, name, value). Returns (id, name) of keys whose value occurs in `text`.
pub fn find<'a>(values: &[(&'a str, &'a str, &str)], text: &str) -> Vec<(&'a str, &'a str)> {
    let mut patterns = Vec::new();
    let mut owner = Vec::new();
    for (i, (_, _, v)) in values.iter().enumerate() {
        if !eligible(v) {
            continue;
        }
        for p in variants(v) {
            patterns.push(p);
            owner.push(i);
        }
    }
    if patterns.is_empty() {
        return Vec::new();
    }
    let Ok(ac) = AhoCorasick::new(&patterns) else { return Vec::new() };
    let mut hit = vec![false; values.len()];
    for m in ac.find_overlapping_iter(text) {
        hit[owner[m.pattern().as_usize()]] = true;
    }
    values
        .iter()
        .zip(hit)
        .filter(|(_, h)| *h)
        .map(|((id, name, _), _)| (*id, *name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_raw_and_encoded() {
        let v = "ghp_Abc123Def456Ghi789Jkl012Mno345Pqr678";
        let vals = [("1", "gh", v)];
        assert_eq!(find(&vals, &format!("x {v} y")).len(), 1);
        assert_eq!(find(&vals, &BASE64.encode(v.as_bytes())).len(), 1);
        assert_eq!(find(&vals, &v[..20]).len(), 0);
    }

    #[test]
    fn short_or_weak_values_skipped() {
        assert!(!eligible("hunter2"));
        assert!(!eligible("aaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(eligible("ghp_Abc123Def456Ghi789Jkl012Mno345Pqr678"));
    }
}
