#![allow(dead_code)]

use std::fmt::{self, Write as _};
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use crate::http_common::{Conn, HELLO, Resp, get_with, pattern};

pub const MAX_RANGES: usize = 64;
pub const MISSING: usize = 4;
const DEFAULT_SEEDS: [u64; 4] = [1, 2, 0xB1A2_E5E7, 0xDEAD_BEEF];
const DEFAULT_CASES: usize = 150;
const OTHER_TAG: &str = "\"00000000000000000000\"";
const HUGE: &str = "99999999999999999999999";

pub struct SplitMix(u64);

impl SplitMix {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }

    fn weighted(&mut self, weights: &[u64]) -> usize {
        let mut roll = self.below(weights.iter().sum());
        for (i, w) in weights.iter().enumerate() {
            if roll < *w {
                return i;
            }
            roll -= w;
        }
        weights.len() - 1
    }
}

pub struct FileModel {
    pub path: &'static str,
    pub ctype: &'static str,
    pub identity: Vec<u8>,
    pub gz: Option<Vec<u8>>,
    pub br: Option<Vec<u8>>,
}

pub fn files() -> Vec<FileModel> {
    let text = |path, identity: Vec<u8>, gz: Option<Vec<u8>>, br: Option<Vec<u8>>| FileModel {
        path,
        ctype: "text/plain",
        identity,
        gz,
        br,
    };
    vec![
        text("hello.txt", HELLO.to_vec(), None, None),
        text(
            "plain.txt",
            b"Precompressed plain content".to_vec(),
            Some(b"GZIP-BYTES".to_vec()),
            Some(b"BROTLI-BYTES".to_vec()),
        ),
        text("data.txt", pattern(4096), Some(pattern(300)), None),
        text("empty.txt", Vec::new(), None, None),
        text("missing.txt", Vec::new(), None, None),
    ]
}

pub fn install(root: &Path) {
    std::fs::write(root.join("data.txt"), pattern(4096)).unwrap();
    std::fs::write(root.join("data.txt.gz"), pattern(300)).unwrap();
    std::fs::write(root.join("empty.txt"), b"").unwrap();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Identity,
    Gzip,
    Br,
}

impl Variant {
    const ALL: [Variant; 3] = [Variant::Identity, Variant::Gzip, Variant::Br];

    fn index(self) -> usize {
        self as usize
    }

    fn accept_encoding(self) -> Option<&'static str> {
        match self {
            Variant::Identity => None,
            Variant::Gzip => Some("gzip"),
            Variant::Br => Some("br"),
        }
    }

    fn token(self) -> Option<&'static str> {
        self.accept_encoding()
    }
}

impl FileModel {
    fn bytes(&self, v: Variant) -> Option<&[u8]> {
        match v {
            Variant::Identity => Some(&self.identity),
            Variant::Gzip => self.gz.as_deref(),
            Variant::Br => self.br.as_deref(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Validators {
    pub etag: String,
    pub last_modified: String,
    pub mtime: u64,
}

pub struct Learned {
    pub cache_control: String,
    validators: Vec<[Option<Validators>; 3]>,
}

impl Learned {
    fn get(&self, file: usize, v: Variant) -> &Validators {
        self.validators[file][v.index()]
            .as_ref()
            .expect("validators learned for every existing variant")
    }
}

pub fn learn(addr: SocketAddr, files: &[FileModel]) -> Result<Learned, String> {
    let mut cache_control: Option<String> = None;
    let mut validators = Vec::new();
    for (idx, file) in files.iter().enumerate() {
        let mut row: [Option<Validators>; 3] = [None, None, None];
        if idx == MISSING {
            validators.push(row);
            continue;
        }
        for v in Variant::ALL {
            let Some(expected) = file.bytes(v) else {
                continue;
            };
            let headers: Vec<(&str, &str)> = v
                .accept_encoding()
                .map(|ae| vec![("Accept-Encoding", ae)])
                .unwrap_or_default();
            let path = format!("/{}", file.path);
            let first = get_with(addr, &path, &headers);
            let second = get_with(addr, &path, &headers);
            let label = format!("{} ({v:?})", file.path);
            if first.status != 200 || first.body != expected {
                return Err(format!(
                    "{label}: expected 200 with the fixture bytes, got {}",
                    first.status
                ));
            }
            if first.header("content-encoding") != v.token() {
                return Err(format!(
                    "{label}: Content-Encoding is {:?}",
                    first.header("content-encoding")
                ));
            }
            if first.header("content-type") != Some(file.ctype) {
                return Err(format!(
                    "{label}: Content-Type is {:?}, expected {}",
                    first.header("content-type"),
                    file.ctype
                ));
            }
            let etag = first.header("etag").ok_or(format!("{label}: no ETag"))?;
            let lm = first
                .header("last-modified")
                .ok_or(format!("{label}: no Last-Modified"))?;
            if second.header("etag") != Some(etag) {
                return Err(format!("{label}: ETag changed between identical requests"));
            }
            let mtime = httpdate::parse_http_date(lm)
                .map_err(|e| format!("{label}: bad Last-Modified {lm:?}: {e}"))?
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let cc = first
                .header("cache-control")
                .ok_or(format!("{label}: no Cache-Control"))?
                .to_owned();
            if *cache_control.get_or_insert_with(|| cc.clone()) != cc {
                return Err(format!("{label}: Cache-Control differs between files"));
            }
            row[v.index()] = Some(Validators {
                etag: etag.to_owned(),
                last_modified: lm.to_owned(),
                mtime,
            });
        }
        let tags: Vec<&str> = row.iter().flatten().map(|v| v.etag.as_str()).collect();
        for (i, a) in tags.iter().enumerate() {
            if tags[i + 1..].contains(a) {
                return Err(format!("{}: two variants share ETag {a}", file.path));
            }
        }
        validators.push(row);
    }
    Ok(Learned {
        cache_control: cache_control.ok_or("no file learned")?,
        validators,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Num {
    Lit(u64),
    Huge,
}

impl Num {
    fn value(self) -> u64 {
        match self {
            Num::Lit(v) => v,
            Num::Huge => u64::MAX,
        }
    }

    fn render(self) -> String {
        match self {
            Num::Lit(v) => v.to_string(),
            Num::Huge => HUGE.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spec {
    Span(Num, Num),
    From(Num),
    Suffix(Num),
}

impl Spec {
    fn render(self) -> String {
        match self {
            Spec::Span(a, b) => format!("{}-{}", a.render(), b.render()),
            Spec::From(a) => format!("{}-", a.render()),
            Spec::Suffix(n) => format!("-{}", n.render()),
        }
    }

    fn resolve(self, size: u64) -> Option<(u64, u64)> {
        match self {
            Spec::Span(a, b) => {
                let (a, b) = (a.value(), b.value());
                (a < size && b >= a).then(|| (a, b.min(size - 1)))
            }
            Spec::From(a) => (a.value() < size).then(|| (a.value(), size - 1)),
            Spec::Suffix(n) => {
                let n = n.value();
                (n > 0 && size > 0).then(|| (size.saturating_sub(n), size - 1))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeKind {
    None,
    Valid { specs: Vec<Spec>, upper_unit: bool },
    Malformed(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfRange {
    None,
    Strong,
    Weak,
    OtherTag,
    DateEqual,
    DateOther,
    Garbage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inm {
    None,
    Strong,
    Weak,
    Other,
    Star,
    ListWithMatch,
    Garbage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ims {
    None,
    Equal,
    Before,
    After,
    Garbage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ae {
    None,
    Identity,
    Gzip,
    Br,
    GzipBr,
    BrZeroGzip,
    GzipZero,
    Deflate,
    GzipHalfBrZero,
}

impl Ae {
    const ALL: [Ae; 9] = [
        Ae::None,
        Ae::Identity,
        Ae::Gzip,
        Ae::Br,
        Ae::GzipBr,
        Ae::BrZeroGzip,
        Ae::GzipZero,
        Ae::Deflate,
        Ae::GzipHalfBrZero,
    ];

    fn header(self) -> Option<&'static str> {
        match self {
            Ae::None => None,
            Ae::Identity => Some("identity"),
            Ae::Gzip => Some("gzip"),
            Ae::Br => Some("br"),
            Ae::GzipBr => Some("gzip, br"),
            Ae::BrZeroGzip => Some("br;q=0, gzip"),
            Ae::GzipZero => Some("gzip;q=0"),
            Ae::Deflate => Some("deflate"),
            Ae::GzipHalfBrZero => Some("gzip;q=0.5, br;q=0"),
        }
    }

    fn wants(self) -> (bool, bool) {
        match self {
            Ae::Gzip | Ae::BrZeroGzip | Ae::GzipHalfBrZero => (false, true),
            Ae::Br => (true, false),
            Ae::GzipBr => (true, true),
            Ae::None | Ae::Identity | Ae::GzipZero | Ae::Deflate => (false, false),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rid {
    None,
    Valid(&'static str),
    Invalid(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Req {
    pub file: usize,
    pub head: bool,
    pub range: RangeKind,
    pub if_range: IfRange,
    pub inm: Inm,
    pub ims: Ims,
    pub ae: Ae,
    pub rid: Rid,
}

const MALFORMED: [&str; 8] = [
    "bytes=",
    "bytes=abc",
    "bytes=1",
    "bytes=-",
    "bytes=+1-2",
    "items=0-1",
    "bytes=1-2-3",
    "bytes=0-1,x",
];
const VALID_IDS: [&str; 4] = ["req-0001", "a", "Trace-ID-42", "abc123"];
const INVALID_IDS: [&str; 4] = [
    "has space",
    "under_score",
    "----",
    "this-identifier-is-deliberately-longer-than-sixty-four-characters-xx",
];

fn gen_num(rng: &mut SplitMix, size: u64) -> Num {
    if rng.chance(1, 30) {
        return Num::Huge;
    }
    let candidates = [
        0,
        1,
        size / 2,
        size.saturating_sub(1),
        size,
        size + 1,
        size + 100,
        rng.below(size + 1),
        rng.below(size + 1),
    ];
    Num::Lit(rng.pick(&candidates))
}

fn gen_spec(rng: &mut SplitMix, size: u64) -> Spec {
    match rng.below(3) {
        0 => Spec::Span(gen_num(rng, size), gen_num(rng, size)),
        1 => Spec::From(gen_num(rng, size)),
        _ => Spec::Suffix(gen_num(rng, size)),
    }
}

fn gen_range(rng: &mut SplitMix, size: u64) -> RangeKind {
    match rng.weighted(&[30, 50, 20]) {
        0 => RangeKind::None,
        1 => {
            let count = match rng.weighted(&[60, 35, 5]) {
                0 => 1,
                1 => 2 + rng.below(5) as usize,
                _ => MAX_RANGES + 1,
            };
            let specs = if count > MAX_RANGES {
                (0..count as u64)
                    .map(|i| Spec::Span(Num::Lit(i), Num::Lit(i)))
                    .collect()
            } else {
                (0..count).map(|_| gen_spec(rng, size)).collect()
            };
            RangeKind::Valid {
                specs,
                upper_unit: rng.chance(1, 8),
            }
        }
        _ => RangeKind::Malformed(rng.pick(&MALFORMED)),
    }
}

pub fn gen_case(seed: u64, index: usize, files: &[FileModel]) -> Vec<Req> {
    let mut rng = SplitMix::new(seed ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let len = 2 + rng.below(5) as usize;
    (0..len)
        .map(|_| {
            let file = rng.weighted(&[2, 3, 3, 1, 1]);
            let size = files[file].identity.len() as u64;
            let range = gen_range(&mut rng, size);
            let has_range = range != RangeKind::None;
            let (num, den) = if has_range { (1, 2) } else { (1, 10) };
            let if_range = if rng.chance(num, den) {
                rng.pick(&[
                    IfRange::Strong,
                    IfRange::Weak,
                    IfRange::OtherTag,
                    IfRange::DateEqual,
                    IfRange::DateOther,
                    IfRange::Garbage,
                ])
            } else {
                IfRange::None
            };
            let inm = if rng.chance(1, 4) {
                rng.pick(&[
                    Inm::Strong,
                    Inm::Weak,
                    Inm::Other,
                    Inm::Star,
                    Inm::ListWithMatch,
                    Inm::Garbage,
                ])
            } else {
                Inm::None
            };
            let ims = if rng.chance(1, 5) {
                rng.pick(&[Ims::Equal, Ims::Before, Ims::After, Ims::Garbage])
            } else {
                Ims::None
            };
            let ae = if rng.chance(11, 20) {
                Ae::None
            } else {
                rng.pick(&Ae::ALL)
            };
            let rid = match rng.weighted(&[60, 25, 15]) {
                0 => Rid::None,
                1 => Rid::Valid(rng.pick(&VALID_IDS)),
                _ => Rid::Invalid(rng.pick(&INVALID_IDS)),
            };
            Req {
                file,
                head: rng.chance(1, 3),
                range,
                if_range,
                inm,
                ims,
                ae,
                rid,
            }
        })
        .collect()
}

pub fn gen_cases(seed: u64, count: usize, files: &[FileModel]) -> Vec<Vec<Req>> {
    (0..count).map(|i| gen_case(seed, i, files)).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    None,
    RangeEndOffByOne,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stats {
    pub full: usize,
    pub single: usize,
    pub multi: usize,
    pub not_modified: usize,
    pub unsatisfiable: usize,
    pub not_found: usize,
    pub gzip: usize,
    pub br: usize,
    pub head_pairs: usize,
    pub ignored_range: usize,
}

impl Stats {
    pub fn merge(&mut self, o: &Stats) {
        self.full += o.full;
        self.single += o.single;
        self.multi += o.multi;
        self.not_modified += o.not_modified;
        self.unsatisfiable += o.unsatisfiable;
        self.not_found += o.not_found;
        self.gzip += o.gzip;
        self.br += o.br;
        self.head_pairs += o.head_pairs;
        self.ignored_range += o.ignored_range;
    }

    pub fn covers_every_outcome(&self) -> Result<(), String> {
        let checks = [
            ("200 full", self.full),
            ("206 single", self.single),
            ("206 multipart", self.multi),
            ("304", self.not_modified),
            ("416", self.unsatisfiable),
            ("404", self.not_found),
            ("gzip variant", self.gzip),
            ("br variant", self.br),
            ("HEAD/GET pair", self.head_pairs),
            ("ignored Range", self.ignored_range),
        ];
        let missing: Vec<_> = checks
            .iter()
            .filter(|(_, n)| *n == 0)
            .map(|(l, _)| *l)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!("generator never produced: {}", missing.join(", ")))
        }
    }
}

enum Outcome {
    NotModified,
    Full,
    Single(u64, u64),
    Multi(Vec<(u64, u64)>),
    Unsatisfiable,
    NotFound,
}

enum BodyExpect {
    Empty,
    Bytes(Vec<u8>),
    Multipart {
        ranges: Vec<(u64, u64)>,
        size: u64,
        ctype: &'static str,
        identity: Vec<u8>,
    },
    Any,
}

pub struct Expect {
    status: u16,
    exact: Vec<(&'static str, String)>,
    absent: Vec<&'static str>,
    vary_has_accept_encoding: bool,
    body: BodyExpect,
    outcome: Outcome,
    variant: Variant,
    range_ignored: bool,
}

fn select(file: &FileModel, req: &Req) -> Variant {
    if req.range != RangeKind::None {
        return Variant::Identity;
    }
    let (br, gz) = req.ae.wants();
    if br && file.br.is_some() {
        Variant::Br
    } else if gz && file.gz.is_some() {
        Variant::Gzip
    } else {
        Variant::Identity
    }
}

fn date_at(secs: u64) -> String {
    httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(secs))
}

fn if_range_valid(kind: IfRange) -> bool {
    matches!(kind, IfRange::Strong | IfRange::DateEqual)
}

fn outcome_of(req: &Req, file: &FileModel) -> Outcome {
    if file.path == "missing.txt" {
        return Outcome::NotFound;
    }
    let not_modified = if req.inm != Inm::None {
        matches!(
            req.inm,
            Inm::Strong | Inm::Weak | Inm::Star | Inm::ListWithMatch
        )
    } else {
        matches!(req.ims, Ims::Equal | Ims::After)
    };
    if not_modified {
        return Outcome::NotModified;
    }
    let size = file.identity.len() as u64;
    let candidate = match &req.range {
        RangeKind::Valid { specs, .. } => {
            let ranges: Vec<_> = specs.iter().filter_map(|s| s.resolve(size)).collect();
            let total: u64 = ranges.iter().map(|(a, b)| b - a + 1).sum();
            if ranges.is_empty() {
                Outcome::Unsatisfiable
            } else if ranges.len() > MAX_RANGES || total > size {
                Outcome::Full
            } else if ranges.len() == 1 {
                Outcome::Single(ranges[0].0, ranges[0].1)
            } else {
                Outcome::Multi(ranges)
            }
        }
        _ => Outcome::Full,
    };
    let range_outcome = matches!(
        candidate,
        Outcome::Single(..) | Outcome::Multi(_) | Outcome::Unsatisfiable
    );
    if range_outcome && req.if_range != IfRange::None && !if_range_valid(req.if_range) {
        Outcome::Full
    } else {
        candidate
    }
}

pub fn expect(req: &Req, files: &[FileModel], learned: &Learned, mutation: Mutation) -> Expect {
    let file = &files[req.file];
    let outcome = outcome_of(req, file);
    let variant = select(file, req);
    if matches!(outcome, Outcome::NotFound) {
        return Expect {
            status: 404,
            exact: Vec::new(),
            absent: vec!["etag", "content-range", "content-encoding"],
            vary_has_accept_encoding: false,
            body: BodyExpect::Any,
            outcome,
            variant,
            range_ignored: false,
        };
    }
    let v = learned.get(req.file, variant);
    let size = file.identity.len() as u64;
    let mut exact = vec![
        ("etag", v.etag.clone()),
        ("last-modified", v.last_modified.clone()),
        ("cache-control", learned.cache_control.clone()),
        ("accept-ranges", "bytes".to_owned()),
    ];
    let mut absent = Vec::new();
    match variant.token() {
        Some(token) => exact.push(("content-encoding", token.to_owned())),
        None => absent.push("content-encoding"),
    }
    let variant_bytes = file
        .bytes(variant)
        .expect("selected variant exists")
        .to_vec();
    let ctype = file.ctype;
    let (status, body) = match &outcome {
        Outcome::NotModified => {
            absent.push("content-range");
            (304, BodyExpect::Empty)
        }
        Outcome::Full => {
            absent.push("content-range");
            exact.push(("content-length", variant_bytes.len().to_string()));
            exact.push(("content-type", ctype.to_owned()));
            (200, BodyExpect::Bytes(variant_bytes))
        }
        Outcome::Single(a, b) => {
            let shown_end = if mutation == Mutation::RangeEndOffByOne {
                b + 1
            } else {
                *b
            };
            exact.push(("content-range", format!("bytes {a}-{shown_end}/{size}")));
            exact.push(("content-length", (shown_end - a + 1).to_string()));
            exact.push(("content-type", ctype.to_owned()));
            (
                206,
                BodyExpect::Bytes(file.identity[*a as usize..=*b as usize].to_vec()),
            )
        }
        Outcome::Multi(ranges) => (
            206,
            BodyExpect::Multipart {
                ranges: ranges.clone(),
                size,
                ctype,
                identity: file.identity.clone(),
            },
        ),
        Outcome::Unsatisfiable => {
            exact.push(("content-range", format!("bytes */{size}")));
            exact.push(("content-length", "0".to_owned()));
            (416, BodyExpect::Empty)
        }
        Outcome::NotFound => unreachable!("handled above"),
    };
    Expect {
        status,
        exact,
        absent,
        vary_has_accept_encoding: variant != Variant::Identity,
        body,
        range_ignored: req.range != RangeKind::None && matches!(outcome, Outcome::Full),
        outcome,
        variant,
    }
}

pub struct Mismatch {
    pub what: String,
    pub expected: String,
    pub observed: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\n  expected: {}\n  observed: {}",
            self.what, self.expected, self.observed
        )
    }
}

fn mismatch<T>(
    what: &str,
    expected: impl fmt::Display,
    observed: impl fmt::Display,
) -> Result<T, Mismatch> {
    Err(Mismatch {
        what: what.to_owned(),
        expected: expected.to_string(),
        observed: observed.to_string(),
    })
}

fn preview(body: &[u8]) -> String {
    let shown: String = String::from_utf8_lossy(&body[..body.len().min(60)])
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect();
    format!("{} bytes {shown:?}", body.len())
}

fn multipart_body(
    boundary: &str,
    ranges: &[(u64, u64)],
    size: u64,
    ctype: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    for (a, b) in ranges {
        out.extend_from_slice(
            format!("--{boundary}\r\nContent-Type: {ctype}\r\nContent-Range: bytes {a}-{b}/{size}\r\n\r\n")
                .as_bytes(),
        );
        out.extend_from_slice(&data[*a as usize..=*b as usize]);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

pub fn check(exp: &Expect, resp: &Resp, head: bool) -> Result<(), Mismatch> {
    if resp.status != exp.status {
        return mismatch("status", exp.status, resp.status);
    }
    for (name, want) in &exp.exact {
        match resp.header(name) {
            Some(got) if got == want => {}
            got => return mismatch(&format!("header {name}"), want, got.unwrap_or("<absent>")),
        }
    }
    for name in &exp.absent {
        if let Some(got) = resp.header(name) {
            return mismatch(&format!("header {name} must be absent"), "<absent>", got);
        }
    }
    if exp.vary_has_accept_encoding && !resp.tokens("vary").iter().any(|t| t == "accept-encoding") {
        return mismatch(
            "header vary",
            "contains Accept-Encoding",
            resp.header("vary").unwrap_or("<absent>"),
        );
    }
    if resp.header("x-content-type-options") != Some("nosniff") {
        return mismatch(
            "header x-content-type-options",
            "nosniff",
            resp.header("x-content-type-options").unwrap_or("<absent>"),
        );
    }
    if resp.header("x-frame-options") != Some("DENY") {
        return mismatch(
            "header x-frame-options",
            "DENY",
            resp.header("x-frame-options").unwrap_or("<absent>"),
        );
    }
    if resp.tokens("connection").iter().any(|t| t == "close") {
        return mismatch(
            "connection persistence",
            "connection stays open",
            "Connection: close",
        );
    }
    match &exp.body {
        BodyExpect::Any => Ok(()),
        _ if head => {
            if resp.body.is_empty() {
                Ok(())
            } else {
                mismatch("HEAD body", "no body", preview(&resp.body))
            }
        }
        BodyExpect::Empty => {
            if resp.body.is_empty() {
                Ok(())
            } else {
                mismatch("body", "empty", preview(&resp.body))
            }
        }
        BodyExpect::Bytes(want) => {
            if &resp.body == want {
                Ok(())
            } else {
                mismatch("body bytes", preview(want), preview(&resp.body))
            }
        }
        BodyExpect::Multipart {
            ranges,
            size,
            ctype,
            identity,
        } => {
            let header = resp.header("content-type").unwrap_or("");
            let Some(boundary) = header.strip_prefix("multipart/byteranges; boundary=") else {
                return mismatch(
                    "content-type",
                    "multipart/byteranges; boundary=<token>",
                    header,
                );
            };
            let want = multipart_body(boundary, ranges, *size, ctype, identity);
            if resp.header("content-length") != Some(want.len().to_string().as_str()) {
                return mismatch(
                    "multipart content-length",
                    want.len(),
                    resp.header("content-length").unwrap_or("<absent>"),
                );
            }
            if resp.body == want {
                Ok(())
            } else {
                mismatch("multipart body", preview(&want), preview(&resp.body))
            }
        }
    }
}

const REPRESENTATION_HEADERS: [&str; 9] = [
    "content-length",
    "content-type",
    "content-range",
    "etag",
    "last-modified",
    "cache-control",
    "accept-ranges",
    "content-encoding",
    "vary",
];

fn compare_head_and_get(head: &Resp, get: &Resp) -> Result<(), Mismatch> {
    if head.status != get.status {
        return mismatch("HEAD status equals GET status", get.status, head.status);
    }
    for name in REPRESENTATION_HEADERS {
        if head.header(name) != get.header(name) && !(get.status == 304 && name == "content-length")
        {
            return mismatch(
                &format!("HEAD header {name} equals GET"),
                get.header(name).unwrap_or("<absent>"),
                head.header(name).unwrap_or("<absent>"),
            );
        }
    }
    Ok(())
}

fn is_generated_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check_request_id(rid: &Rid, resp: &Resp, seen: &mut Vec<String>) -> Result<(), Mismatch> {
    let got = resp.header("x-request-id").unwrap_or("<absent>");
    match rid {
        Rid::Valid(id) => {
            if got != *id {
                return mismatch("X-Request-ID echo", *id, got);
            }
        }
        Rid::None | Rid::Invalid(_) => {
            if !is_generated_id(got) {
                return mismatch("generated X-Request-ID", "12 lowercase hex characters", got);
            }
            if seen.iter().any(|s| s == got) {
                return mismatch(
                    "X-Request-ID leaked from an earlier request",
                    "a fresh id",
                    got,
                );
            }
            seen.push(got.to_owned());
        }
    }
    Ok(())
}

pub struct WireReq {
    pub method: &'static str,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl fmt::Display for WireReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.path)?;
        for (k, v) in &self.headers {
            write!(f, "\n         {k}: {v}")?;
        }
        Ok(())
    }
}

fn render_headers(req: &Req, files: &[FileModel], learned: &Learned) -> Vec<(String, String)> {
    let file = &files[req.file];
    let mut out = Vec::new();
    if let RangeKind::Valid { specs, upper_unit } = &req.range {
        let unit = if *upper_unit { "Bytes" } else { "bytes" };
        let list: Vec<_> = specs.iter().map(|s| s.render()).collect();
        out.push(("Range".to_owned(), format!("{unit}={}", list.join(","))));
    } else if let RangeKind::Malformed(raw) = &req.range {
        out.push(("Range".to_owned(), (*raw).to_owned()));
    }
    if file.path != "missing.txt" {
        let sel = select(file, req);
        let sv = learned.get(req.file, sel);
        let iv = learned.get(req.file, Variant::Identity);
        let if_range = match req.if_range {
            IfRange::None => None,
            IfRange::Strong => Some(iv.etag.clone()),
            IfRange::Weak => Some(format!("W/{}", iv.etag)),
            IfRange::OtherTag => Some(OTHER_TAG.to_owned()),
            IfRange::DateEqual => Some(iv.last_modified.clone()),
            IfRange::DateOther => Some(date_at(iv.mtime.saturating_sub(7200))),
            IfRange::Garbage => Some("not-a-validator".to_owned()),
        };
        out.extend(if_range.map(|v| ("If-Range".to_owned(), v)));
        let inm = match req.inm {
            Inm::None => None,
            Inm::Strong => Some(sv.etag.clone()),
            Inm::Weak => Some(format!("W/{}", sv.etag)),
            Inm::Other => Some(OTHER_TAG.to_owned()),
            Inm::Star => Some("*".to_owned()),
            Inm::ListWithMatch => Some(format!("\"zzz\", W/\"yyy\", {}", sv.etag)),
            Inm::Garbage => Some("unquoted-garbage".to_owned()),
        };
        out.extend(inm.map(|v| ("If-None-Match".to_owned(), v)));
        let ims = match req.ims {
            Ims::None => None,
            Ims::Equal => Some(sv.last_modified.clone()),
            Ims::Before => Some(date_at(sv.mtime.saturating_sub(3600))),
            Ims::After => Some(date_at(sv.mtime + 3600)),
            Ims::Garbage => Some("yesterday-ish".to_owned()),
        };
        out.extend(ims.map(|v| ("If-Modified-Since".to_owned(), v)));
    }
    out.extend(
        req.ae
            .header()
            .map(|v| ("Accept-Encoding".to_owned(), v.to_owned())),
    );
    match &req.rid {
        Rid::None => {}
        Rid::Valid(id) | Rid::Invalid(id) => {
            out.push(("X-Request-ID".to_owned(), (*id).to_owned()))
        }
    }
    out
}

struct Step {
    wire: WireReq,
    expect_idx: usize,
    head: bool,
    pairs_with_previous: bool,
    rid: Rid,
}

fn plan(
    case: &[Req],
    files: &[FileModel],
    learned: &Learned,
    mutation: Mutation,
) -> (Vec<Step>, Vec<Expect>) {
    let mut steps = Vec::new();
    let mut expects = Vec::new();
    for req in case {
        let headers = render_headers(req, files, learned);
        let path = format!("/{}", files[req.file].path);
        expects.push(expect(req, files, learned, mutation));
        let expect_idx = expects.len() - 1;
        if req.head {
            steps.push(Step {
                wire: WireReq {
                    method: "HEAD",
                    path: path.clone(),
                    headers: headers.clone(),
                },
                expect_idx,
                head: true,
                pairs_with_previous: false,
                rid: req.rid.clone(),
            });
        }
        steps.push(Step {
            wire: WireReq {
                method: "GET",
                path,
                headers,
            },
            expect_idx,
            head: false,
            pairs_with_previous: req.head,
            rid: req.rid.clone(),
        });
    }
    (steps, expects)
}

pub fn wire_log(case: &[Req], files: &[FileModel], learned: &Learned) -> Vec<String> {
    plan(case, files, learned, Mutation::None)
        .0
        .iter()
        .map(|s| s.wire.to_string())
        .collect()
}

pub struct CaseError {
    pub at: usize,
    pub wire: Vec<String>,
    pub mismatch: Mismatch,
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "non-text panic".to_owned())
}

pub fn run_case(
    addr: SocketAddr,
    files: &[FileModel],
    learned: &Learned,
    case: &[Req],
    mutation: Mutation,
    stats: &mut Stats,
) -> Result<(), CaseError> {
    let (steps, expects) = plan(case, files, learned, mutation);
    let wire: Vec<String> = steps.iter().map(|s| s.wire.to_string()).collect();
    let fail = |at: usize, mismatch: Mismatch| CaseError {
        at,
        wire: wire.clone(),
        mismatch,
    };
    let mut conn = match catch_unwind(AssertUnwindSafe(|| Conn::open(addr))) {
        Ok(c) => c,
        Err(p) => {
            return Err(fail(
                0,
                Mismatch {
                    what: "connect".into(),
                    expected: "connection accepted".into(),
                    observed: panic_text(p),
                },
            ));
        }
    };
    let mut seen_ids: Vec<String> = Vec::new();
    let mut previous: Option<Resp> = None;
    for (i, step) in steps.iter().enumerate() {
        let headers: Vec<(&str, &str)> = step
            .wire
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let sent = catch_unwind(AssertUnwindSafe(|| {
            conn.send(step.wire.method, &step.wire.path, &headers)
        }));
        let resp = match sent {
            Ok(r) => r,
            Err(p) => {
                return Err(fail(
                    i,
                    Mismatch {
                        what: "transport".into(),
                        expected: "a well-formed response on the persistent connection".into(),
                        observed: panic_text(p),
                    },
                ));
            }
        };
        let exp = &expects[step.expect_idx];
        check(exp, &resp, step.head).map_err(|m| fail(i, m))?;
        check_request_id(&step.rid, &resp, &mut seen_ids).map_err(|m| fail(i, m))?;
        if step.pairs_with_previous {
            let head = previous.as_ref().expect("HEAD precedes its GET");
            compare_head_and_get(head, &resp).map_err(|m| fail(i, m))?;
            stats.head_pairs += 1;
        }
        if !step.head {
            record(stats, exp);
        }
        previous = Some(resp);
    }
    Ok(())
}

fn record(stats: &mut Stats, exp: &Expect) {
    match &exp.outcome {
        Outcome::Full => stats.full += 1,
        Outcome::Single(..) => stats.single += 1,
        Outcome::Multi(_) => stats.multi += 1,
        Outcome::NotModified => stats.not_modified += 1,
        Outcome::Unsatisfiable => stats.unsatisfiable += 1,
        Outcome::NotFound => stats.not_found += 1,
    }
    if exp.range_ignored {
        stats.ignored_range += 1;
    }
    match exp.variant {
        Variant::Gzip => stats.gzip += 1,
        Variant::Br => stats.br += 1,
        Variant::Identity => {}
    }
}

pub fn shrink(case: &[Req], mut fails: impl FnMut(&[Req]) -> bool) -> Vec<Req> {
    let mut best = case.to_vec();
    let mut budget = 300usize;
    loop {
        let mut changed = false;
        let mut i = 0;
        while i < best.len() && best.len() > 1 && budget > 0 {
            let mut candidate = best.clone();
            candidate.remove(i);
            budget -= 1;
            if fails(&candidate) {
                best = candidate;
                changed = true;
            } else {
                i += 1;
            }
        }
        for i in 0..best.len() {
            for simplify in SIMPLIFIERS {
                if budget == 0 {
                    break;
                }
                let mut candidate = best.clone();
                if !simplify(&mut candidate[i]) {
                    continue;
                }
                budget -= 1;
                if fails(&candidate) {
                    best = candidate;
                    changed = true;
                }
            }
        }
        if !changed || budget == 0 {
            return best;
        }
    }
}

type Simplifier = fn(&mut Req) -> bool;

const SIMPLIFIERS: [Simplifier; 8] = [
    |r| std::mem::replace(&mut r.head, false),
    |r| std::mem::replace(&mut r.rid, Rid::None) != Rid::None,
    |r| std::mem::replace(&mut r.ae, Ae::None) != Ae::None,
    |r| std::mem::replace(&mut r.ims, Ims::None) != Ims::None,
    |r| std::mem::replace(&mut r.inm, Inm::None) != Inm::None,
    |r| std::mem::replace(&mut r.if_range, IfRange::None) != IfRange::None,
    |r| match &mut r.range {
        RangeKind::Valid { specs, .. } if specs.len() > 1 => {
            specs.truncate(1);
            true
        }
        _ => false,
    },
    |r| std::mem::replace(&mut r.range, RangeKind::None) != RangeKind::None,
];

pub struct RunConfig {
    pub seeds: Vec<u64>,
    pub cases: usize,
    pub single_seed: bool,
}

fn parse_u64(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

pub fn config_from_env() -> RunConfig {
    let env_seed = std::env::var("BLAZE_CONFORMANCE_SEED").ok();
    let seeds = match &env_seed {
        Some(raw) => vec![
            parse_u64(raw)
                .unwrap_or_else(|| panic!("BLAZE_CONFORMANCE_SEED is not a u64: {raw:?}")),
        ],
        None => DEFAULT_SEEDS.to_vec(),
    };
    let cases = std::env::var("BLAZE_CONFORMANCE_CASES")
        .ok()
        .map(|raw| {
            parse_u64(&raw)
                .unwrap_or_else(|| panic!("BLAZE_CONFORMANCE_CASES is not a number: {raw:?}"))
                as usize
        })
        .unwrap_or(DEFAULT_CASES);
    RunConfig {
        seeds,
        cases,
        single_seed: env_seed.is_some(),
    }
}

pub fn run_seed(
    addr: SocketAddr,
    files: &[FileModel],
    learned: &Learned,
    seed: u64,
    cases: usize,
    mutation: Mutation,
    stats: &mut Stats,
) -> Result<(), String> {
    for index in 0..cases {
        let case = gen_case(seed, index, files);
        let mut local = Stats::default();
        let Err(first) = run_case(addr, files, learned, &case, mutation, &mut local) else {
            stats.merge(&local);
            continue;
        };
        let minimized = shrink(&case, |c| {
            run_case(addr, files, learned, c, mutation, &mut Stats::default()).is_err()
        });
        let min_err = run_case(
            addr,
            files,
            learned,
            &minimized,
            mutation,
            &mut Stats::default(),
        )
        .err()
        .unwrap_or(CaseError {
            at: first.at,
            wire: first.wire.clone(),
            mismatch: Mismatch {
                what: "(minimized case no longer fails)".into(),
                expected: String::new(),
                observed: String::new(),
            },
        });
        return Err(report(seed, index, &first, &min_err));
    }
    Ok(())
}

fn numbered(lines: &[String]) -> String {
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let _ = writeln!(out, "  {:>2}. {line}", i + 1);
    }
    out
}

fn report(seed: u64, index: usize, first: &CaseError, minimized: &CaseError) -> String {
    format!(
        "conformance mismatch\nseed: {seed}\ncase: {index}\nreplay: BLAZE_CONFORMANCE_SEED={seed} cargo test --test conformance -- --nocapture\n\nrequest sequence (one persistent connection):\n{}\nfailed at request {}: {}\n\nminimized sequence ({} requests):\n{}\nminimized failure at request {}: {}\n",
        numbered(&first.wire),
        first.at + 1,
        first.mismatch,
        minimized.wire.len(),
        numbered(&minimized.wire),
        minimized.at + 1,
        minimized.mismatch,
    )
}
