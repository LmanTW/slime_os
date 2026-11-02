const POLY: u32 = 0xEDB8_8320;

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ POLY
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

const TABLE: [u32; 256] = build_table();

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(data);
    crc.finish()
}

/// CRC-32/IEEE over data that arrives in pieces, such as a GPT entry array read one sector at a
/// time. `finish` of the pieces equals [`crc32`] of their concatenation.
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    pub const fn new() -> Self {
        Self { state: !0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        for byte in data {
            self.state = TABLE[((self.state ^ *byte as u32) & 0xFF) as usize] ^ (self.state >> 8);
        }
    }

    pub const fn finish(self) -> u32 {
        !self.state
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    /// Published CRC-32/IEEE vectors, `0xcbf43926` over `"123456789"` being the
    /// standard check value. The table is built at compile time from `POLY`, so a
    /// wrong polynomial or a reflected-vs-normal mix-up yields a self-consistent
    /// checksum that every internal round-trip would still accept. These are the
    /// only assertions anchoring it to the real algorithm.
    #[test]
    fn published_vectors_match() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xe8b7_be43);
        assert_eq!(crc32(b"abc"), 0x3524_41c2);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414f_a339
        );
    }

    /// Pieces of any split give the checksum of the whole.
    #[test]
    fn pieces_equal_the_whole() {
        let data: alloc::vec::Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for split in [0, 1, 7, 512, 999, 1000] {
            let mut crc = Crc32::new();
            crc.update(&data[..split]);
            crc.update(&data[split..]);
            assert_eq!(crc.finish(), crc32(&data), "split at {split}");
        }
    }

    /// Every byte value, so no table entry can be wrong without being caught.
    /// A single bad entry would otherwise only surface for inputs containing
    /// that byte.
    #[test]
    fn every_table_entry_is_exercised() {
        let all: alloc::vec::Vec<u8> = (0..=255u8).collect();
        assert_eq!(crc32(&all), 0x2905_8c73);
    }

    /// CRC-32 detects the corruptions it is used here to detect: a flipped bit,
    /// a transposition, and a length change. Bootstate and the store rely on
    /// exactly these.
    #[test]
    fn plausible_corruptions_change_the_checksum() {
        let base = b"slime-os-bootstate";
        let mut flipped = *base;
        flipped[3] ^= 0x01;
        assert_ne!(crc32(base), crc32(&flipped));

        let mut swapped = *base;
        swapped.swap(0, 1);
        assert_ne!(crc32(base), crc32(&swapped));

        assert_ne!(crc32(base), crc32(b"slime-os-bootstat"));
        assert_ne!(crc32(b"\0"), crc32(b"\0\0"));
    }
}
