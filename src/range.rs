/// Beyond this many ranges a request is answered with the full body, so a
/// `bytes=0-,0-,0-...` header cannot amplify the response.
pub const MAX_RANGES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeSpec {
    /// Header absent or syntactically malformed: ignore it and send the full body.
    Ignore,
    /// Syntactically valid but nothing is satisfiable: answer 416.
    Unsatisfiable,
    /// Inclusive `(start, end)` pairs, all within the representation.
    Ranges(Vec<(u64, u64)>),
}

fn digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // A number too large for u64 is simply past any real file size.
    Some(s.parse().unwrap_or(u64::MAX))
}

pub fn parse_range_header(header: Option<&str>, size: u64) -> RangeSpec {
    let Some(header) = header else {
        return RangeSpec::Ignore;
    };
    let Some(spec) = header
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case("bytes="))
        .map(|_| header[6..].trim())
        .filter(|s| !s.is_empty())
    else {
        return RangeSpec::Ignore;
    };

    let mut out = Vec::new();
    let mut saw_range = false;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        saw_range = true;
        let Some((first, last)) = part.split_once('-') else {
            return RangeSpec::Ignore;
        };
        let (start, end) = if first.is_empty() {
            let Some(suffix) = digits(last) else {
                return RangeSpec::Ignore;
            };
            if suffix == 0 || size == 0 {
                continue;
            }
            (size.saturating_sub(suffix), size - 1)
        } else {
            let Some(start) = digits(first) else {
                return RangeSpec::Ignore;
            };
            let end = if last.is_empty() {
                u64::MAX
            } else {
                match digits(last) {
                    Some(e) => e,
                    None => return RangeSpec::Ignore,
                }
            };
            (start, end)
        };
        if start >= size || end < start {
            continue;
        }
        out.push((start, end.min(size - 1)));
    }

    match (saw_range, out.is_empty()) {
        (false, _) => RangeSpec::Ignore,
        (true, true) => RangeSpec::Unsatisfiable,
        (true, false) => RangeSpec::Ranges(out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(h: &str, size: u64) -> RangeSpec {
        parse_range_header(Some(h), size)
    }

    #[test]
    fn single_suffix_and_open_ended() {
        assert_eq!(p("bytes=0-4", 18), RangeSpec::Ranges(vec![(0, 4)]));
        assert_eq!(p("bytes=-5", 18), RangeSpec::Ranges(vec![(13, 17)]));
        assert_eq!(p("bytes=10-", 18), RangeSpec::Ranges(vec![(10, 17)]));
        assert_eq!(p("bytes=0-999", 18), RangeSpec::Ranges(vec![(0, 17)]));
        assert_eq!(p("bytes=-999", 18), RangeSpec::Ranges(vec![(0, 17)]));
    }

    #[test]
    fn multiple_ranges_keep_order() {
        assert_eq!(
            p("bytes=0-4, 7-11", 18),
            RangeSpec::Ranges(vec![(0, 4), (7, 11)])
        );
    }

    #[test]
    fn unsatisfiable_vs_malformed() {
        assert_eq!(p("bytes=100-200", 18), RangeSpec::Unsatisfiable);
        assert_eq!(p("bytes=-0", 18), RangeSpec::Unsatisfiable);
        assert_eq!(p("bytes=0-4", 0), RangeSpec::Unsatisfiable);
        assert_eq!(p("bytes=9-3", 18), RangeSpec::Unsatisfiable);
        for bad in [
            "bytes=",
            "bytes=abc",
            "bytes=1",
            "bytes=-",
            "bytes=+1-2",
            "items=0-1",
            "bytes=1-x",
        ] {
            assert_eq!(p(bad, 18), RangeSpec::Ignore, "{bad}");
        }
        assert_eq!(parse_range_header(None, 18), RangeSpec::Ignore);
    }

    #[test]
    fn partially_satisfiable_keeps_valid_members() {
        assert_eq!(p("bytes=100-200,0-1", 18), RangeSpec::Ranges(vec![(0, 1)]));
    }

    #[test]
    fn huge_numbers_do_not_panic() {
        assert_eq!(
            p("bytes=99999999999999999999999-", 18),
            RangeSpec::Unsatisfiable
        );
        assert_eq!(
            p("bytes=0-99999999999999999999999", 18),
            RangeSpec::Ranges(vec![(0, 17)])
        );
    }
}
