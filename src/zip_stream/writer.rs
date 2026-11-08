//! ZIP binary format writer for non-seekable sinks.
//!
//! The `zip` crate only writes to seekable sinks, so entries are written here as
//! STORED with data descriptors (CRC and sizes follow the data), which a socket can
//! carry without seeking back.

use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use super::crc32::crc32_update;

const ZIP64_LIMIT: u64 = 0xFFFF_FFFF;

/// MS-DOS date/time in UTC; anything outside 1980..=2107 becomes 1980-01-01.
fn dos_datetime(t: Option<SystemTime>) -> (u16, u16) {
    const FALLBACK: (u16, u16) = (0, 0x0021);
    let secs = t
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1980..=2107).contains(&year) {
        return FALLBACK;
    }
    let time = ((rem / 3600) << 11) | (((rem % 3600) / 60) << 5) | ((rem % 60) / 2);
    let date = ((year - 1980) << 9) | (month << 5) | day;
    (time as u16, date as u16)
}

struct CentralEntry {
    name: Vec<u8>,
    crc: u32,
    size: u64,
    offset: u64,
    descriptor_z64: bool,
    time: u16,
    date: u16,
}

pub(super) struct StreamZip<W: Write> {
    out: W,
    pos: u64,
    entries: Vec<CentralEntry>,
    limit: u64,
}

impl<W: Write> StreamZip<W> {
    pub(super) fn new(out: W) -> Self {
        Self {
            out,
            pos: 0,
            entries: Vec::new(),
            limit: ZIP64_LIMIT,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    /// Writes exactly `size` bytes from `src`; a file that shrinks mid-read is an error
    /// rather than a silently corrupt entry.
    pub(super) fn add_file(
        &mut self,
        name: &str,
        modified: Option<SystemTime>,
        size: u64,
        src: &mut impl Read,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > usize::from(u16::MAX) {
            return Ok(());
        }
        let z64 = size >= self.limit;
        let (time, date) = dos_datetime(modified);
        let offset = self.pos;

        let mut h = Vec::with_capacity(30 + name_bytes.len() + 20);
        h.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        h.extend_from_slice(&(if z64 { 45u16 } else { 20 }).to_le_bytes());
        h.extend_from_slice(&0x0808u16.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&time.to_le_bytes());
        h.extend_from_slice(&date.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        let sizes = if z64 { u32::MAX } else { 0 };
        h.extend_from_slice(&sizes.to_le_bytes());
        h.extend_from_slice(&sizes.to_le_bytes());
        h.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        h.extend_from_slice(&(if z64 { 20u16 } else { 0 }).to_le_bytes());
        h.extend_from_slice(name_bytes);
        if z64 {
            h.extend_from_slice(&1u16.to_le_bytes());
            h.extend_from_slice(&16u16.to_le_bytes());
            h.extend_from_slice(&[0u8; 16]);
        }
        self.put(&h)?;

        let mut crc = 0u32;
        let mut remaining = size;
        while remaining > 0 {
            let want = buf
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            let n = src.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "file shrank while archiving",
                ));
            }
            crc = crc32_update(crc, &buf[..n]);
            self.put(&buf[..n])?;
            remaining -= n as u64;
        }

        let mut d = Vec::with_capacity(24);
        d.extend_from_slice(&0x0807_4B50u32.to_le_bytes());
        d.extend_from_slice(&crc.to_le_bytes());
        if z64 {
            d.extend_from_slice(&size.to_le_bytes());
            d.extend_from_slice(&size.to_le_bytes());
        } else {
            d.extend_from_slice(&(size as u32).to_le_bytes());
            d.extend_from_slice(&(size as u32).to_le_bytes());
        }
        self.put(&d)?;

        self.entries.push(CentralEntry {
            name: name_bytes.to_vec(),
            crc,
            size,
            offset,
            descriptor_z64: z64,
            time,
            date,
        });
        Ok(())
    }

    pub(super) fn finish(mut self) -> io::Result<W> {
        let cd_start = self.pos;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let z64 = e.descriptor_z64 || e.offset >= self.limit;
            let mut c = Vec::with_capacity(46 + e.name.len() + 28);
            c.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
            c.extend_from_slice(&((3u16 << 8) | 45).to_le_bytes());
            c.extend_from_slice(&(if z64 { 45u16 } else { 20 }).to_le_bytes());
            c.extend_from_slice(&0x0808u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&e.time.to_le_bytes());
            c.extend_from_slice(&e.date.to_le_bytes());
            c.extend_from_slice(&e.crc.to_le_bytes());
            let field = |v: u64| if z64 { u32::MAX } else { v as u32 };
            c.extend_from_slice(&field(e.size).to_le_bytes());
            c.extend_from_slice(&field(e.size).to_le_bytes());
            c.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            c.extend_from_slice(&(if z64 { 28u16 } else { 0 }).to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes());
            c.extend_from_slice(&field(e.offset).to_le_bytes());
            c.extend_from_slice(&e.name);
            if z64 {
                c.extend_from_slice(&1u16.to_le_bytes());
                c.extend_from_slice(&24u16.to_le_bytes());
                c.extend_from_slice(&e.size.to_le_bytes());
                c.extend_from_slice(&e.size.to_le_bytes());
                c.extend_from_slice(&e.offset.to_le_bytes());
            }
            self.put(&c)?;
        }
        let cd_size = self.pos - cd_start;
        let count = entries.len() as u64;
        let z64 = count >= 0xFFFF || cd_start >= self.limit || cd_size >= self.limit;
        if z64 {
            let eocd64_at = self.pos;
            let mut r = Vec::with_capacity(56 + 20);
            r.extend_from_slice(&0x0606_4B50u32.to_le_bytes());
            r.extend_from_slice(&44u64.to_le_bytes());
            r.extend_from_slice(&45u16.to_le_bytes());
            r.extend_from_slice(&45u16.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&count.to_le_bytes());
            r.extend_from_slice(&count.to_le_bytes());
            r.extend_from_slice(&cd_size.to_le_bytes());
            r.extend_from_slice(&cd_start.to_le_bytes());
            r.extend_from_slice(&0x0706_4B50u32.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&eocd64_at.to_le_bytes());
            r.extend_from_slice(&1u32.to_le_bytes());
            self.put(&r)?;
        }
        let mut e = Vec::with_capacity(22);
        e.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        let n16 = if z64 { u16::MAX } else { count as u16 };
        e.extend_from_slice(&n16.to_le_bytes());
        e.extend_from_slice(&n16.to_le_bytes());
        e.extend_from_slice(&(if z64 { u32::MAX } else { cd_size as u32 }).to_le_bytes());
        e.extend_from_slice(&(if z64 { u32::MAX } else { cd_start as u32 }).to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        self.put(&e)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn dos_datetime_known_values() {
        let y2000 = UNIX_EPOCH + std::time::Duration::from_secs(946_684_800);
        assert_eq!(dos_datetime(Some(y2000)), (0, (20 << 9) | (1 << 5) | 1));
        assert_eq!(dos_datetime(Some(UNIX_EPOCH)), (0, 0x0021));
        assert_eq!(dos_datetime(None), (0, 0x0021));
    }

    fn build_archive(limit: u64, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = StreamZip::new(Vec::new());
        zip.limit = limit;
        let mut buf = vec![0u8; 7];
        for (name, data) in files {
            zip.add_file(
                name,
                Some(UNIX_EPOCH),
                data.len() as u64,
                &mut Cursor::new(*data),
                &mut buf,
            )
            .unwrap();
        }
        zip.finish().unwrap()
    }

    fn assert_roundtrip(bytes: Vec<u8>, files: &[(&str, &[u8])]) {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("valid archive");
        assert_eq!(archive.len(), files.len());
        for (name, data) in files {
            let mut entry = archive.by_name(name).expect("entry");
            let mut got = Vec::new();
            entry.read_to_end(&mut got).expect("crc-checked read");
            assert_eq!(&got, data);
        }
    }

    #[test]
    fn standard_archive_round_trips() {
        let files: &[(&str, &[u8])] = &[
            ("a.txt", b"alpha"),
            ("dir/b.bin", &[0u8, 1, 2, 3, 255]),
            ("empty", b""),
            ("\u{e9}.txt", b"utf8"),
        ];
        assert_roundtrip(build_archive(ZIP64_LIMIT, files), files);
    }

    #[test]
    fn zip64_structures_round_trip() {
        let files: &[(&str, &[u8])] = &[("x", b"some bytes here"), ("y/z", b"more")];
        assert_roundtrip(build_archive(1, files), files);
    }

    #[test]
    fn empty_archive_is_valid() {
        assert_roundtrip(build_archive(ZIP64_LIMIT, &[]), &[]);
    }

    #[test]
    fn shrinking_file_is_an_error() {
        let mut zip = StreamZip::new(Vec::new());
        let err = zip
            .add_file("f", None, 10, &mut Cursor::new(&b"abc"[..]), &mut [0u8; 4])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
