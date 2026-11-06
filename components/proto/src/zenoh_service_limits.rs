//! The Zenoh service limits record (`contracts/zenoh-service-limits/v1`).
//!
//! A record is 48 bytes. `decode` checks every byte the layout defines and each limit against its bound, and returns the
//! six limits. The limits are declared numbers: what the service does with them is the service's.

pub use crate::zenoh_service_limits_wire::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Short,
    BadMagic,
    UnsupportedVersion,
    BadSize,
    UnknownRequiredFlags,
    OutOfBounds,
}

/// The six limits of `Limits` in `zenoh-service-grants/v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub holders: u32,
    pub ring_slots: u32,
    pub sample_bytes: u32,
    pub key_bytes: u32,
    pub local_subscriptions: u32,
    pub stack_bytes: u32,
}

/// The most the service was built to hold of each limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ceilings {
    pub holders: u32,
    pub ring_slots: u32,
    pub sample_bytes: u32,
    pub key_bytes: u32,
    pub local_subscriptions: u32,
    pub stack_bytes: u32,
}

impl Limits {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != RECORD_LEN {
            return Err(DecodeError::Short);
        }
        let record = WireLimitsRecord::decode(bytes).ok_or(DecodeError::Short)?;
        if record.magic != RECORD_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if record.format_version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion);
        }
        if record.record_size as usize != RECORD_BYTES {
            return Err(DecodeError::BadSize);
        }
        if record.required_flags != 0 {
            return Err(DecodeError::UnknownRequiredFlags);
        }
        let within = |value: u32, high: u32| (1..=high).contains(&value);
        if !(within(record.holders, MAX_COUNT)
            && within(record.ring_slots, MAX_COUNT)
            && within(record.sample_bytes, MAX_SAMPLE_BYTES)
            && within(record.key_bytes, MAX_KEY_BYTES)
            && within(record.local_subscriptions, MAX_COUNT)
            && within(record.stack_bytes, MAX_STACK_BYTES))
        {
            return Err(DecodeError::OutOfBounds);
        }
        Ok(Self {
            holders: record.holders,
            ring_slots: record.ring_slots,
            sample_bytes: record.sample_bytes,
            key_bytes: record.key_bytes,
            local_subscriptions: record.local_subscriptions,
            stack_bytes: record.stack_bytes,
        })
    }

    /// Whether the service built with `ceilings` honors these limits. Every limit is at most its ceiling. The ring depth and
    /// the sample size are equal to it, because the core fixes both in its types and cannot enforce a smaller declaration.
    /// The holders, subscriptions and key length are held by the rows, which the builder compares with the record, so a
    /// declaration below the ceiling is honored for them.
    pub fn honored_by(&self, ceilings: &Ceilings) -> bool {
        self.within(ceilings)
            && self.ring_slots == ceilings.ring_slots
            && self.sample_bytes == ceilings.sample_bytes
    }

    /// Whether every limit is at most the matching ceiling.
    pub fn within(&self, ceilings: &Ceilings) -> bool {
        self.holders <= ceilings.holders
            && self.ring_slots <= ceilings.ring_slots
            && self.sample_bytes <= ceilings.sample_bytes
            && self.key_bytes <= ceilings.key_bytes
            && self.local_subscriptions <= ceilings.local_subscriptions
            && self.stack_bytes <= ceilings.stack_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(values: [u32; 6]) -> [u8; RECORD_LEN] {
        WireLimitsRecord {
            magic: RECORD_MAGIC,
            format_version: FORMAT_VERSION,
            record_size: RECORD_BYTES as u32,
            required_flags: 0,
            holders: values[0],
            ring_slots: values[1],
            sample_bytes: values[2],
            key_bytes: values[3],
            local_subscriptions: values[4],
            stack_bytes: values[5],
        }
        .encode()
    }

    const CEILINGS: Ceilings = Ceilings {
        holders: 2,
        ring_slots: 4,
        sample_bytes: 12,
        key_bytes: 64,
        local_subscriptions: 3,
        stack_bytes: 32768,
    };

    #[test]
    fn a_limit_above_a_ceiling_is_refused_and_one_at_it_is_not() {
        let at = [2, 4, 12, 64, 3, 32768];
        let limits = Limits::decode(&record(at)).expect("a record at every ceiling");
        assert!(limits.within(&CEILINGS));
        for index in 0..6 {
            let mut over = at;
            over[index] += 1;
            let limits = Limits::decode(&record(over)).expect("one over is still a valid record");
            assert!(
                !limits.within(&CEILINGS),
                "limit {index} one over its ceiling"
            );
            let mut below = at;
            below[index] -= 1;
            let limits = Limits::decode(&record(below)).expect("one below");
            assert!(
                limits.within(&CEILINGS),
                "limit {index} one below its ceiling"
            );
        }
    }

    #[test]
    fn a_declaration_the_fixed_core_cannot_honor_is_refused() {
        let at = [2, 4, 12, 64, 3, 32768];
        let honored = |values: [u32; 6]| {
            Limits::decode(&record(values))
                .unwrap()
                .honored_by(&CEILINGS)
        };
        assert!(honored(at), "a record equal to the ceilings is honored");
        // The core's types fix the ring depth and the sample size, so a smaller declaration cannot be enforced.
        let mut ring = at;
        ring[1] = 1;
        assert!(!honored(ring), "a ring of one slot under a core of four");
        let mut sample = at;
        sample[2] = 1;
        assert!(
            !honored(sample),
            "a sample of one byte under a core of twelve"
        );
        // The rows hold these, so a declaration below the ceiling is honored.
        for index in [0, 3, 4] {
            let mut below = at;
            below[index] -= 1;
            assert!(honored(below), "limit {index} one below its ceiling");
        }
        // Above a ceiling is refused for every limit, as before.
        for index in 0..6 {
            let mut over = at;
            over[index] += 1;
            assert!(!honored(over), "limit {index} one over its ceiling");
        }
    }

    #[test]
    fn a_record_that_is_corrupt_or_out_of_bounds_does_not_decode() {
        let honest = record([2, 4, 12, 64, 3, 32768]);
        assert!(Limits::decode(&honest).is_ok());
        assert_eq!(Limits::decode(&honest[..47]), Err(DecodeError::Short));
        let mut longer = honest.to_vec();
        longer.push(0);
        assert_eq!(Limits::decode(&longer), Err(DecodeError::Short));
        let mut magic = honest;
        magic[0] = b'X';
        assert_eq!(Limits::decode(&magic), Err(DecodeError::BadMagic));
        let mut version = honest;
        version[OFF_RECORD_FORMAT_VERSION] = 2;
        assert_eq!(
            Limits::decode(&version),
            Err(DecodeError::UnsupportedVersion)
        );
        let mut size = honest;
        size[OFF_RECORD_RECORD_SIZE] = 49;
        assert_eq!(Limits::decode(&size), Err(DecodeError::BadSize));
        let mut flags = honest;
        flags[OFF_RECORD_REQUIRED_FLAGS] = 1;
        assert_eq!(
            Limits::decode(&flags),
            Err(DecodeError::UnknownRequiredFlags)
        );
        for index in 0..6 {
            let mut zero = [2, 4, 12, 64, 3, 32768];
            zero[index] = 0;
            assert_eq!(
                Limits::decode(&record(zero)),
                Err(DecodeError::OutOfBounds),
                "limit {index} at zero"
            );
        }
        for (index, high) in [
            (0, MAX_COUNT),
            (1, MAX_COUNT),
            (2, MAX_SAMPLE_BYTES),
            (3, MAX_KEY_BYTES),
            (4, MAX_COUNT),
        ] {
            let mut over = [2, 4, 12, 64, 3, 32768];
            over[index] = high + 1;
            assert_eq!(
                Limits::decode(&record(over)),
                Err(DecodeError::OutOfBounds),
                "limit {index} above its bound"
            );
        }
    }
}
