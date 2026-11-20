//! The file name a server suggests in `Content-Disposition` (RFC 6266, RFC 8187).
//!
//! The value is advisory and comes from an untrusted server, so only the last path
//! segment is kept and anything that could escape the current directory, name a device
//! or hide an alternate stream is refused.

use percent_encoding::percent_decode_str;

const MAX_NAME_BYTES: usize = 255;

/// `filename*` wins over `filename` when both are present and usable.
pub(super) fn suggested_name(header: &str) -> Option<String> {
    let mut plain = None;
    let mut extended = None;
    for (key, value) in parameters(header) {
        if key.eq_ignore_ascii_case("filename*") {
            extended = extended.or_else(|| decode_ext_value(&value));
        } else if key.eq_ignore_ascii_case("filename") {
            plain = plain.or(Some(value));
        }
    }
    extended
        .and_then(|n| sanitize(&n))
        .or_else(|| plain.and_then(|n| sanitize(&n)))
}

/// Splits `; key=value` parameters, honouring quoted strings and `\` escapes inside them.
fn parameters(header: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = header.chars().peekable();
    // The disposition type comes first and carries no value.
    for c in chars.by_ref() {
        if c == ';' {
            break;
        }
    }
    loop {
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ';' {
                break;
            }
            key.push(c);
            chars.next();
        }
        let key = key.trim().to_owned();
        let mut value = String::new();
        if chars.peek() == Some(&'=') {
            chars.next();
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(escaped) = chars.next() {
                                value.push(escaped);
                            }
                        }
                        '"' => break,
                        other => value.push(other),
                    }
                }
                while let Some(&c) = chars.peek() {
                    if c == ';' {
                        break;
                    }
                    chars.next();
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c == ';' {
                        break;
                    }
                    value.push(c);
                    chars.next();
                }
                value = value.trim().to_owned();
            }
        }
        if !key.is_empty() {
            out.push((key, value));
        }
        if chars.next().is_none() {
            break;
        }
    }
    out
}

/// `charset'language'percent-encoded-value`. Only UTF-8 is accepted.
fn decode_ext_value(value: &str) -> Option<String> {
    let mut parts = value.splitn(3, '\'');
    let charset = parts.next()?;
    let _language = parts.next()?;
    let encoded = parts.next()?;
    if !charset.eq_ignore_ascii_case("utf-8") {
        return None;
    }
    percent_decode_str(encoded)
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

fn sanitize(raw: &str) -> Option<String> {
    let last = raw.rsplit(['/', '\\']).next()?;
    let name = last.trim().trim_end_matches(['.', ' ']);
    if name.is_empty() || name == "." || name == ".." || name.len() > MAX_NAME_BYTES {
        return None;
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return None;
    }
    if is_device_name(name) {
        return None;
    }
    Some(name.to_owned())
}

/// Windows opens `CON.txt` as the console, whatever the extension.
fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|p| {
        stem.strip_prefix(p)
            .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
    })
}

#[cfg(test)]
mod tests {
    use super::suggested_name;

    fn name(header: &str) -> Option<String> {
        suggested_name(header)
    }

    #[test]
    fn reads_quoted_and_token_filenames() {
        assert_eq!(
            name("attachment; filename=\"a b.zip\"").as_deref(),
            Some("a b.zip")
        );
        assert_eq!(
            name("attachment; filename=data.csv").as_deref(),
            Some("data.csv")
        );
        assert_eq!(
            name("ATTACHMENT; FileName=\"x.bin\"").as_deref(),
            Some("x.bin")
        );
    }

    #[test]
    fn unescapes_quoted_pairs_and_keeps_semicolons_inside_quotes() {
        // An escaped quote is unescaped, and a name containing one is then refused.
        assert_eq!(name("attachment; filename=\"a\\\"b.txt\""), None);
        assert_eq!(
            name("attachment; filename=\"a;b.txt\"").as_deref(),
            Some("a;b.txt")
        );
    }

    #[test]
    fn extended_form_wins_and_decodes_utf8() {
        assert_eq!(
            name("attachment; filename=\"rates.txt\"; filename*=UTF-8''%e2%82%ac%20rates.txt")
                .as_deref(),
            Some("\u{20ac} rates.txt")
        );
        assert_eq!(
            name("attachment; filename*=utf-8'en'caf%C3%A9.txt").as_deref(),
            Some("caf\u{e9}.txt")
        );
    }

    #[test]
    fn unusable_extended_form_falls_back_to_the_plain_one() {
        assert_eq!(
            name("attachment; filename=\"ok.txt\"; filename*=ISO-8859-1''na%EFve.txt").as_deref(),
            Some("ok.txt")
        );
        assert_eq!(
            name("attachment; filename=\"ok.txt\"; filename*=UTF-8''%ff%fe.txt").as_deref(),
            Some("ok.txt")
        );
    }

    #[test]
    fn keeps_only_the_last_path_segment() {
        assert_eq!(
            name("attachment; filename=\"../../etc/passwd\"").as_deref(),
            Some("passwd")
        );
        assert_eq!(
            name("attachment; filename=\"C:\\\\x\\\\evil.exe\"").as_deref(),
            Some("evil.exe")
        );
        assert_eq!(
            name("attachment; filename*=UTF-8''..%2f..%2fstartup.bat").as_deref(),
            Some("startup.bat")
        );
    }

    #[test]
    fn refuses_names_that_are_not_safe_files() {
        for header in [
            "attachment; filename=\"..\"",
            "attachment; filename=\".\"",
            "attachment; filename=\"\"",
            "attachment; filename=\"/\"",
            "attachment; filename=\"a\0b\"",
            "attachment; filename*=UTF-8''a%00b",
            "attachment; filename=\"C:evil.txt\"",
            "attachment; filename=\"file.txt:stream\"",
            "attachment; filename=\"CON\"",
            "attachment; filename=\"nul.txt\"",
            "attachment; filename=\"COM1.log\"",
            "attachment; filename=\"lpt9\"",
            "attachment; filename=\"...\"",
            "attachment",
            "inline",
        ] {
            assert_eq!(name(header), None, "{header}");
        }
        // Windows drops trailing dots and spaces, so the name is saved without them.
        assert_eq!(
            name("attachment; filename=\"dots...\"").as_deref(),
            Some("dots")
        );
        assert_eq!(
            name("attachment; filename=\"com10.txt\"").as_deref(),
            Some("com10.txt")
        );
        let long = format!("attachment; filename=\"{}\"", "a".repeat(256));
        assert_eq!(name(&long), None);
    }
}
