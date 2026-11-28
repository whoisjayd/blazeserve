//! `blaze verify`: check files against SHA-256 and SFV (CRC-32) checksum lists.
//!
//! A list is untrusted input. Only the file name of an entry is used, so nothing outside the
//! list's own folder is opened, and a list that cannot be read in full never passes.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use clap::Args;

use super::download::sibling;
use crate::cli::ansi::Style;
use crate::cli::exit;
use crate::cli::util::sha256_file;
use crate::zip_stream::crc32_update;

const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
const SUMS_FILE: &str = "SHA256SUMS";

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Files to check against FILE.sha256, or else the SHA256SUMS beside them
    #[arg(required_unless_present_any = ["check", "sfv"], conflicts_with_all = ["check", "sfv"])]
    pub files: Vec<PathBuf>,
    /// Check every file named in a `sha256sum` list
    #[arg(short, long, value_name = "LIST", conflicts_with = "sfv")]
    pub check: Option<PathBuf>,
    /// Check every file named in an SFV (CRC-32) list
    #[arg(long, value_name = "LIST")]
    pub sfv: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expected {
    /// Lowercase hex.
    Sha256(String),
    Crc32(u32),
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    /// `None` for a bare digest, which only a `FILE.sha256` may hold.
    name: Option<String>,
    expected: Expected,
}

enum Outcome {
    Matched,
    Mismatched,
    Missing,
    Unchecked(String),
}

/// The last component of a listed path, which is all that is ever opened.
fn file_name_only(listed: &str) -> Option<String> {
    if listed.contains('\0') {
        return None;
    }
    Path::new(listed).file_name()?.to_str().map(str::to_owned)
}

/// Undoes the escaping `sha256sum` applies to a name with a backslash or a line break.
fn unescape(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            _ => return None,
        }
    }
    Some(out)
}

/// `<hex>`, `<hex>  <name>` or `<hex> *<name>`.
fn sha256_line(line: &str) -> Option<Entry> {
    let (escaped, line) = match line.strip_prefix('\\') {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let hex = line.get(..64)?;
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let rest = &line[64..];
    let name = if rest.trim().is_empty() {
        None
    } else {
        if !rest.starts_with([' ', '\t']) {
            return None;
        }
        let listed = rest
            .strip_prefix("  ")
            .or_else(|| rest.strip_prefix(" *"))
            .unwrap_or_else(|| rest.trim_start());
        let listed = if escaped {
            unescape(listed)?
        } else {
            listed.to_owned()
        };
        Some(file_name_only(&listed)?)
    };
    Some(Entry {
        name,
        expected: Expected::Sha256(hex.to_ascii_lowercase()),
    })
}

/// `<name> <crc32 hex>`; the name may hold spaces and may be quoted.
fn sfv_line(line: &str) -> Option<Entry> {
    let (name, hex) = line.trim_end().rsplit_once([' ', '\t'])?;
    if hex.len() != 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let name = name.trim();
    let name = name
        .strip_prefix('"')
        .and_then(|n| n.strip_suffix('"'))
        .unwrap_or(name);
    Some(Entry {
        name: Some(file_name_only(name)?),
        expected: Expected::Crc32(u32::from_str_radix(hex, 16).ok()?),
    })
}

/// Every entry of a list, or the number of the first line that is not one.
fn parse(
    text: &str,
    comment: char,
    line_entry: fn(&str) -> Option<Entry>,
) -> Result<Vec<Entry>, usize> {
    text.trim_start_matches('\u{feff}')
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty() && !line.starts_with(comment))
        .map(|(i, line)| line_entry(line).ok_or(i + 1))
        .collect()
}

fn parse_sha256_list(text: &str) -> Result<Vec<Entry>, usize> {
    parse(text, '#', sha256_line)
}

fn parse_sfv(text: &str) -> Result<Vec<Entry>, usize> {
    parse(text, ';', sfv_line)
}

#[cfg(fuzzing)]
pub fn parse_lists_for_fuzz(text: &str) -> Vec<String> {
    [parse_sha256_list(text), parse_sfv(text)]
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .filter_map(|e| e.name)
        .collect()
}

fn load(list: &Path, parse: fn(&str) -> Result<Vec<Entry>, usize>) -> Result<Vec<Entry>, String> {
    let shown = list.display();
    let cannot = |e: io::Error| format!("cannot read {shown}: {e}");
    if !std::fs::metadata(list).map_err(cannot)?.is_file() {
        return Err(format!("{shown} is not a file"));
    }
    let mut text = String::new();
    std::fs::File::open(list)
        .map_err(cannot)?
        .take(MAX_LIST_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(cannot)?;
    if text.len() as u64 > MAX_LIST_BYTES {
        return Err(format!("{shown} is too large to be a checksum list"));
    }
    let entries =
        parse(&text).map_err(|line| format!("{shown}: line {line} is not a checksum entry"))?;
    if entries.is_empty() {
        return Err(format!("{shown} lists no checksums"));
    }
    Ok(entries)
}

fn crc32_file(path: &Path) -> io::Result<u32> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; super::READ_BUF];
    let mut crc = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(crc);
        }
        crc = crc32_update(crc, &buf[..n]);
    }
}

/// Hashes `path` once and compares it with every digest listed for it.
fn check(path: &Path, expected: &[Expected]) -> Outcome {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        // A pipe or a device could block for ever.
        Ok(_) => return Outcome::Unchecked("not a regular file".to_owned()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Outcome::Missing,
        Err(e) => return Outcome::Unchecked(e.to_string()),
    }
    let actual = match expected.first() {
        Some(Expected::Crc32(_)) => crc32_file(path).map(Expected::Crc32),
        _ => sha256_file(path).map(Expected::Sha256),
    };
    match actual {
        Ok(actual) if expected.iter().all(|e| *e == actual) => Outcome::Matched,
        Ok(_) => Outcome::Mismatched,
        Err(e) => Outcome::Unchecked(e.to_string()),
    }
}

/// The digests that `FILE.sha256`, or else `SHA256SUMS`, records for `file`.
fn expected_for(file: &Path) -> Result<Vec<Expected>, String> {
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("not a file name")?;
    let sidecar = sibling(file, ".sha256");
    let (list, own) = if sidecar.exists() {
        (sidecar, true)
    } else {
        (file.with_file_name(SUMS_FILE), false)
    };
    if !list.exists() {
        return Err(format!("no {name}.sha256 or {SUMS_FILE} beside it"));
    }
    let entries = load(&list, parse_sha256_list)?;
    // A file's own sidecar with a single digest covers it even under another name.
    let sole = own && entries.len() == 1;
    let found: Vec<Expected> = entries
        .into_iter()
        .filter(|e| sole || e.name.as_deref() == Some(name))
        .map(|e| e.expected)
        .collect();
    if found.is_empty() {
        return Err(format!("not listed in {}", list.display()));
    }
    Ok(found)
}

/// A listed name must not be able to drive the terminal.
fn printable(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[derive(Default)]
struct Tally {
    total: usize,
    mismatched: usize,
    unchecked: usize,
}

impl Tally {
    fn report(&mut self, name: &str, outcome: Outcome) {
        let style = Style::stdout();
        let name = printable(name);
        self.total += 1;
        match outcome {
            Outcome::Matched => anstream::println!("{}       {name}", style.green("ok")),
            Outcome::Mismatched => {
                self.mismatched += 1;
                anstream::println!("{}   {name}", style.red("FAILED"));
            }
            Outcome::Missing => {
                self.unchecked += 1;
                anstream::println!("{}  {name}", style.red("missing"));
            }
            Outcome::Unchecked(why) => {
                self.unchecked += 1;
                anstream::println!("{}  {name}: {}", style.red("skipped"), printable(&why));
            }
        }
    }

    /// A mismatch outranks a file that could not be checked: it means bad data.
    fn code(&self) -> u8 {
        if self.mismatched + self.unchecked == 0
            && self.total > 1
            && !crate::cli::ansi::quiet()
            && std::io::IsTerminal::is_terminal(&std::io::stdout())
        {
            anstream::println!(
                "{}",
                Style::stdout().bold(&format!("All {} files match.", self.total))
            );
        }
        if self.mismatched + self.unchecked > 0 {
            anstream::eprintln!(
                "{} {} of {} did not match, {} could not be checked",
                Style::stderr().red("error:"),
                self.mismatched,
                self.total,
                self.unchecked
            );
        }
        if self.mismatched > 0 {
            exit::INTEGRITY
        } else if self.unchecked > 0 {
            exit::OTHER
        } else {
            0
        }
    }
}

pub fn verify(args: VerifyArgs) -> Result<u8, String> {
    let mut tally = Tally::default();
    let listed = args
        .check
        .as_deref()
        .map(|l| (l, parse_sha256_list as fn(&str) -> _))
        .or_else(|| args.sfv.as_deref().map(|l| (l, parse_sfv as fn(&str) -> _)));
    if let Some((list, parser)) = listed {
        let dir = list.parent().unwrap_or(Path::new(""));
        for (i, entry) in load(list, parser)?.into_iter().enumerate() {
            let Some(name) = entry.name else {
                return Err(format!(
                    "{}: entry {} has a digest and no file name",
                    list.display(),
                    i + 1
                ));
            };
            let outcome = check(&dir.join(&name), &[entry.expected]);
            tally.report(&name, outcome);
        }
    } else {
        for file in &args.files {
            let outcome = if !file.exists() {
                Outcome::Missing
            } else {
                match expected_for(file) {
                    Ok(expected) => check(file, &expected),
                    Err(why) => Outcome::Unchecked(why),
                }
            };
            tally.report(&file.display().to_string(), outcome);
        }
    }
    Ok(tally.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn sha(name: &str) -> Entry {
        Entry {
            name: Some(name.to_owned()),
            expected: Expected::Sha256(HEX.to_owned()),
        }
    }

    #[test]
    fn reads_the_shapes_sha256sum_writes() {
        let text = format!(
            "\u{feff}# release\r\n{HEX}  a b.bin\r\n\r\n{} *c.bin\n{HEX}\t./d\n",
            HEX.to_ascii_uppercase()
        );
        assert_eq!(
            parse_sha256_list(&text).unwrap(),
            [sha("a b.bin"), sha("c.bin"), sha("d")]
        );
        assert_eq!(parse_sha256_list(HEX).unwrap()[0].name, None);
    }

    #[test]
    fn only_the_file_name_of_an_entry_is_kept() {
        let text = format!("{HEX}  ../../etc/passwd\n{HEX}  /abs/shadow\n");
        assert_eq!(
            parse_sha256_list(&text).unwrap(),
            [sha("passwd"), sha("shadow")]
        );
        assert_eq!(parse_sha256_list(&format!("{HEX}  ..")), Err(1));
    }

    #[test]
    fn a_line_that_is_not_an_entry_fails_the_whole_list() {
        for bad in ["<html>", "abc  file", &format!("{HEX}x  file")] {
            let text = format!("{HEX}  ok\n{bad}\n");
            assert_eq!(parse_sha256_list(&text), Err(2), "{bad}");
        }
        assert_eq!(parse_sfv("name-without-crc\n"), Err(1));
        assert_eq!(parse_sfv("a.bin 1234567\n"), Err(1));
    }

    #[test]
    fn reads_sfv_lines() {
        let entries = parse_sfv("; made by x\n\"a b.bin\" CBF43926\nsub/c d  0000000f\n").unwrap();
        let got: Vec<_> = entries
            .iter()
            .map(|e| (e.name.as_deref().unwrap(), e.expected.clone()))
            .collect();
        assert_eq!(
            got,
            [
                ("a b.bin", Expected::Crc32(0xCBF4_3926)),
                ("c d", Expected::Crc32(15))
            ]
        );
    }

    #[test]
    fn control_characters_are_not_printed() {
        assert_eq!(printable("a\x1b[2Jb\n"), "a?[2Jb?");
    }

    proptest::proptest! {
        #[test]
        fn listed_names_are_never_paths(text in "[0-9a-f \\*\\./\\\\\"\\n]{0,200}") {
            let names = [parse_sha256_list(&text), parse_sfv(&text)]
                .into_iter()
                .filter_map(Result::ok)
                .flatten()
                .filter_map(|e| e.name);
            for name in names {
                proptest::prop_assert!(!name.is_empty() && name != "..");
                proptest::prop_assert!(!name.contains('/'));
            }
        }
    }
}
