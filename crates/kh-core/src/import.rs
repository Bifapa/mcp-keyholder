//! Finds secret-looking fragments in an old `.txt` file so the user can pick what becomes a key.
//! Offsets are UTF-16 code units, ready for highlighting in the web UI.

use regex::Regex;
use serde::Serialize;

use crate::scan::entropy_bits;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub start: usize,
    pub end: usize,
    pub value: String,
    /// What it looks like: "GitHub token", "apikey", "PEM: OPENSSH PRIVATE KEY", ...
    pub label: String,
    pub kind: String,
    /// Suggested name suffix, e.g. "api-key".
    pub suggested: String,
}

const KNOWN: &[(&str, &str, &str)] = &[
    (r"github_pat_[A-Za-z0-9_]{40,}", "GitHub fine-grained PAT", "token"),
    (r"gh[pousr]_[A-Za-z0-9]{30,}", "GitHub token", "token"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key", "api-key"),
    (r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}", "OpenAI-style API key", "api-key"),
    (r"xox[abposr]-[A-Za-z0-9\-]{10,}", "Slack token", "token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id", "access-key-id"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key", "api-key"),
    (r"glpat-[A-Za-z0-9_\-]{20,}", "GitLab token", "token"),
    (r"pk1_[A-Za-z0-9]{20,}", "Porkbun API key", "api-key"),
    (r"sk1_[A-Za-z0-9]{20,}", "Porkbun secret key", "api-secret"),
    (r"npm_[A-Za-z0-9]{30,}", "npm token", "token"),
    (r"hf_[A-Za-z0-9]{30,}", "Hugging Face token", "token"),
];

fn u16_offset(text: &str, byte: usize) -> usize {
    text[..byte].encode_utf16().count()
}

pub fn slug(s: &str) -> String {
    let mut out = String::new();
    let translit = |c: char| -> Option<&'static str> {
        Some(match c {
            'а' => "a", 'б' => "b", 'в' => "v", 'г' => "g", 'д' => "d", 'е' | 'ё' | 'э' => "e", 'ж' => "zh",
            'з' => "z", 'и' | 'й' => "i", 'к' => "k", 'л' => "l", 'м' => "m", 'н' => "n", 'о' => "o",
            'п' => "p", 'р' => "r", 'с' => "s", 'т' => "t", 'у' => "u", 'ф' => "f", 'х' => "h", 'ц' => "c",
            'ч' => "ch", 'ш' => "sh", 'щ' => "sch", 'ы' => "y", 'ю' => "yu", 'я' => "ya", 'ь' | 'ъ' => "",
            _ => return None,
        })
    };
    for c in s.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if let Some(t) = translit(c) {
            out.push_str(t);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    out.chars().take(40).collect()
}

pub fn candidates(text: &str) -> Vec<Candidate> {
    let mut found: Vec<(usize, usize, String, String, String)> = Vec::new(); // byte start, end, label, kind, suggested
    let overlaps = |found: &Vec<(usize, usize, String, String, String)>, s: usize, e: usize| {
        found.iter().any(|(fs, fe, ..)| s < *fe && *fs < e)
    };

    let pem = Regex::new(r"(?s)-----BEGIN ([A-Z0-9 ]+)-----.*?-----END [A-Z0-9 ]+-----").expect("regex");
    for m in pem.captures_iter(text) {
        let whole = m.get(0).expect("match");
        let kind = m.get(1).map_or("", |k| k.as_str()).to_string();
        found.push((whole.start(), whole.end(), format!("PEM: {kind}"), "pem".into(), slug(&kind)));
    }

    for (re, label, suggested) in KNOWN {
        let r = Regex::new(&format!(r"\b{re}")).expect("regex");
        for m in r.find_iter(text) {
            if !overlaps(&found, m.start(), m.end()) {
                found.push((m.start(), m.end(), label.to_string(), "known".into(), suggested.to_string()));
            }
        }
    }

    let kv = Regex::new(r"(?m)^[ \t]*([\p{L}\p{N} _.\-]{1,40}?)[ \t]*[:=][ \t]*(\S[^\r\n]*?)[ \t]*\r?$").expect("regex");
    for c in kv.captures_iter(text) {
        let (Some(k), Some(v)) = (c.get(1), c.get(2)) else { continue };
        if v.as_str().chars().count() < 6 || v.as_str().contains(char::is_whitespace) && entropy_bits(v.as_str()) < 60.0 {
            continue;
        }
        if !overlaps(&found, v.start(), v.end()) {
            found.push((v.start(), v.end(), k.as_str().trim().to_string(), "kv".into(), slug(k.as_str())));
        }
    }

    let tok = Regex::new(r"[A-Za-z0-9_\-+/=.]{20,}").expect("regex");
    for m in tok.find_iter(text) {
        let s = m.as_str();
        if entropy_bits(s) / s.chars().count() as f64 >= 3.5 && !overlaps(&found, m.start(), m.end()) {
            found.push((m.start(), m.end(), "похоже на ключ".into(), "entropy".into(), "key".into()));
        }
    }

    if found.is_empty() {
        let t = text.trim();
        if !t.is_empty() && !t.contains('\n') && t.chars().count() >= 8 {
            let start = text.find(t).unwrap_or(0);
            found.push((start, start + t.len(), "весь файл".into(), "whole".into(), "key".into()));
        }
    }

    found.sort_by_key(|f| f.0);
    found
        .into_iter()
        .map(|(s, e, label, kind, suggested)| Candidate {
            start: u16_offset(text, s),
            end: u16_offset(text, e),
            value: text[s..e].to_string(),
            label,
            kind,
            suggested: if suggested.is_empty() { "key".into() } else { suggested },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn porkbun_style_file() {
        let t = "porkbun — домены\napikey: pk1_aaaaBBBBccccDDDDeeee1111\nsecret: sk1_ffffGGGGhhhhIIIIjjjj2222\nаккаунт: bifastack";
        let c = candidates(t);
        let labels: Vec<&str> = c.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.contains(&"Porkbun API key"));
        assert!(labels.contains(&"Porkbun secret key"));
        let first = &c[0];
        let s16: Vec<u16> = t.encode_utf16().collect();
        assert_eq!(String::from_utf16(&s16[first.start..first.end]).unwrap(), first.value);
    }

    #[test]
    fn single_line_file() {
        let c = candidates("  my-plain-secret-value \n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].value, "my-plain-secret-value");
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("API Key"), "api-key");
        assert_eq!(slug("Логин аккаунта"), "login-akkaunta");
    }
}
