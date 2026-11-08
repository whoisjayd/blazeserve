//! Temporary benchmark directory and the deterministic fixture file written into it.

use crate::cli::util::hex;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub(super) const DEFAULT_SEED: u64 = 0x426c_617a_6545;
pub(super) const FIXTURE_NAME: &str = "fixture.bin";
pub(super) const MIB: u64 = 1024 * 1024;

pub(super) struct TempDir(pub(super) PathBuf);

impl TempDir {
    pub(super) fn create() -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "blazeserve-benchmark-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).map_err(|e| format!("Benchmark failed: {e}"))?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Write `size` pseudo-random bytes derived only from `seed` and return their SHA-256.
/// The chunk size is a multiple of 8, so the stream does not depend on buffering.
pub(super) fn write_fixture(path: &Path, size: u64, seed: u64) -> std::io::Result<String> {
    let mut file = std::fs::File::create(path)?;
    let mut state = seed;
    let mut buf = vec![0u8; MIB as usize];
    let mut hasher = Sha256::new();
    let mut left = size;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        for chunk in buf[..n].chunks_mut(8) {
            let word = splitmix64(&mut state).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    file.flush()?;
    Ok(hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::util::sha256_file;

    #[test]
    fn temp_dir_is_removed_on_drop() {
        let dir = TempDir::create().unwrap();
        let path = dir.0.clone();
        std::fs::write(path.join("f"), b"x").unwrap();
        assert!(path.is_dir());
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn fixture_is_deterministic_and_seed_dependent() {
        let dir = TempDir::create().unwrap();
        let (a, b, c) = (dir.0.join("a"), dir.0.join("b"), dir.0.join("c"));
        let size = MIB + 13;
        let ha = write_fixture(&a, size, 7).unwrap();
        assert_eq!(ha, write_fixture(&b, size, 7).unwrap());
        assert_ne!(ha, write_fixture(&c, size, 8).unwrap());
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert_eq!(std::fs::metadata(&a).unwrap().len(), size);
        assert_eq!(ha, sha256_file(&a).unwrap());
    }
}
