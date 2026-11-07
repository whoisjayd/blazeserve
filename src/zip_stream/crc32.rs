//! Slice-by-8 CRC-32 (IEEE) used for ZIP entry checksums.

const fn crc_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    i = 0;
    while i < 256 {
        let mut c = t[0][i];
        let mut j = 1;
        while j < 8 {
            c = t[0][(c & 0xFF) as usize] ^ (c >> 8);
            t[j][i] = c;
            j += 1;
        }
        i += 1;
    }
    t
}

static CRC: [[u32; 256]; 8] = crc_tables();

pub(super) fn crc32_update(state: u32, data: &[u8]) -> u32 {
    let mut crc = !state;
    let (chunks, remainder) = data.as_chunks::<8>();
    for c in chunks {
        let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ crc;
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = CRC[7][(lo & 0xFF) as usize]
            ^ CRC[6][((lo >> 8) & 0xFF) as usize]
            ^ CRC[5][((lo >> 16) & 0xFF) as usize]
            ^ CRC[4][(lo >> 24) as usize]
            ^ CRC[3][(hi & 0xFF) as usize]
            ^ CRC[2][((hi >> 8) & 0xFF) as usize]
            ^ CRC[1][((hi >> 16) & 0xFF) as usize]
            ^ CRC[0][(hi >> 24) as usize];
    }
    for &b in remainder {
        crc = CRC[0][((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_reference_vectors() {
        assert_eq!(crc32_update(0, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_update(0, b""), 0);
        let whole = crc32_update(0, b"hello world, this is a longer test string!");
        let split = crc32_update(
            crc32_update(0, b"hello world, thi"),
            b"s is a longer test string!",
        );
        assert_eq!(whole, split);
    }
}
