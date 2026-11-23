//! Resource readers resource object.
//!
//! A generation resource object naming, for each generation table the root
//! serves to a declared reader, the instances that may read it. The root holds
//! no component name for these tables: it serves a table to an instance exactly
//! when a row pairs the table's resource id with that instance. A generation
//! without the object has no reader of any of them.
//!
//! It is embedded as a `KIND_RESOURCE` object and authenticated by the
//! generation's per-object digest table. Decoding here assumes integrity has
//! already been verified and enforces only structure. Whether each row names an
//! admitted instance is the root's admission check, because only the root holds
//! the instance table the identities are derived from.

use crate::sha256::Sha256;

include!("generated/resource_reader.rs");
pub const MAX_BYTES: usize = HEADER_BYTES + MAX_ROWS * ENTRY_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnknownRequiredFlags,
    BadBounds,
    BadOrder,
    /// A row names a resource id this contract version does not define.
    UnknownResource,
}

/// One generation table a row can name a reader of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    EntropyAuthority,
    ZenohGrants,
    ZenohLimits,
    NetworkDestinations,
    NetworkInterfaces,
    NetworkApplications,
    BlockRingAuthority,
}

impl Resource {
    pub const ALL: [Self; 7] = [
        Self::EntropyAuthority,
        Self::ZenohGrants,
        Self::ZenohLimits,
        Self::NetworkDestinations,
        Self::NetworkInterfaces,
        Self::NetworkApplications,
        Self::BlockRingAuthority,
    ];

    pub const fn id(self) -> u32 {
        match self {
            Self::EntropyAuthority => RESOURCE_ENTROPY_AUTHORITY,
            Self::ZenohGrants => RESOURCE_ZENOH_GRANTS,
            Self::ZenohLimits => RESOURCE_ZENOH_LIMITS,
            Self::NetworkDestinations => RESOURCE_NETWORK_DESTINATIONS,
            Self::NetworkInterfaces => RESOURCE_NETWORK_INTERFACES,
            Self::NetworkApplications => RESOURCE_NETWORK_APPLICATIONS,
            Self::BlockRingAuthority => RESOURCE_BLOCK_RING_AUTHORITY,
        }
    }

    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            RESOURCE_ENTROPY_AUTHORITY => Some(Self::EntropyAuthority),
            RESOURCE_ZENOH_GRANTS => Some(Self::ZenohGrants),
            RESOURCE_ZENOH_LIMITS => Some(Self::ZenohLimits),
            RESOURCE_NETWORK_DESTINATIONS => Some(Self::NetworkDestinations),
            RESOURCE_NETWORK_INTERFACES => Some(Self::NetworkInterfaces),
            RESOURCE_NETWORK_APPLICATIONS => Some(Self::NetworkApplications),
            RESOURCE_BLOCK_RING_AUTHORITY => Some(Self::BlockRingAuthority),
            _ => None,
        }
    }
}

/// A decoded, structurally validated reader table. Rows are sorted by
/// `(resource, reader_identity)` and unique, so lookup is deterministic.
#[derive(Debug, Clone, Copy)]
pub struct ResourceReaders<'a> {
    bytes: &'a [u8],
    row_count: usize,
}

impl<'a> ResourceReaders<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_BYTES {
            return Err(DecodeError::Truncated);
        }
        if bytes[..8] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if u32_at(bytes, 8)? != FORMAT_VERSION || u32_at(bytes, 12)? as usize != HEADER_BYTES {
            return Err(DecodeError::UnsupportedVersion);
        }
        if u64_at(bytes, 16)? != 0 {
            return Err(DecodeError::UnknownRequiredFlags);
        }
        let row_count = u32_at(bytes, 24)? as usize;
        let total_len = u32_at(bytes, 28)? as usize;
        if row_count > MAX_ROWS
            || total_len != HEADER_BYTES + row_count * ENTRY_BYTES
            || total_len != bytes.len()
        {
            return Err(DecodeError::BadBounds);
        }
        let mut previous = (0u32, [0u8; 32]);
        for index in 0..row_count {
            let entry = entry(bytes, index)?;
            let resource = u32_at(entry, 0)?;
            if Resource::from_id(resource).is_none() {
                return Err(DecodeError::UnknownResource);
            }
            let identity: [u8; 32] = entry[4..].try_into().unwrap();
            if identity == [0; 32] || (index > 0 && (resource, identity) <= previous) {
                return Err(DecodeError::BadOrder);
            }
            previous = (resource, identity);
        }
        Ok(Self { bytes, row_count })
    }

    pub fn row_count(&self) -> usize {
        self.row_count
    }

    /// The resource and reader identity of the `index`th row.
    pub fn row(&self, index: usize) -> Option<(Resource, [u8; 32])> {
        if index >= self.row_count {
            return None;
        }
        let entry = entry(self.bytes, index).ok()?;
        let resource = Resource::from_id(u32_at(entry, 0).ok()?)?;
        Some((resource, entry[4..].try_into().ok()?))
    }

    /// Whether a row declares the instance with `identity` a reader of
    /// `resource`.
    pub fn names(&self, resource: Resource, identity: &[u8; 32]) -> bool {
        (0..self.row_count).any(|index| self.row(index) == Some((resource, *identity)))
    }
}

/// Stable identity derived from an instance name, in this contract's own
/// domain, so no other resource's identity can name a row here.
pub fn reader_identity(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(&(name.len() as u16).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.finalize()
}

fn entry(bytes: &[u8], index: usize) -> Result<&[u8], DecodeError> {
    let offset = HEADER_BYTES + index * ENTRY_BYTES;
    bytes
        .get(offset..offset + ENTRY_BYTES)
        .ok_or(DecodeError::Truncated)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    /// Encode `rows` as given, without sorting or validating them, so a test can
    /// build a table the decoder must refuse.
    fn encode_rows(rows: &[(u32, [u8; 32])]) -> Vec<u8> {
        let total = HEADER_BYTES + rows.len() * ENTRY_BYTES;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(total as u32).to_le_bytes());
        for (resource, identity) in rows {
            bytes.extend_from_slice(&resource.to_le_bytes());
            bytes.extend_from_slice(identity);
        }
        bytes
    }

    const GRANTS: u32 = RESOURCE_ZENOH_GRANTS;
    const LIMITS: u32 = RESOURCE_ZENOH_LIMITS;

    #[test]
    fn a_row_names_one_reader_of_one_resource() {
        let bytes = encode_rows(&[
            (GRANTS, [0x11; 32]),
            (GRANTS, [0x22; 32]),
            (LIMITS, [0x11; 32]),
        ]);
        let table = ResourceReaders::decode(&bytes).expect("decodes");
        assert_eq!(table.row_count(), 3);
        assert!(table.names(Resource::ZenohGrants, &[0x11; 32]));
        assert!(table.names(Resource::ZenohGrants, &[0x22; 32]));
        assert!(table.names(Resource::ZenohLimits, &[0x11; 32]));
        assert!(!table.names(Resource::ZenohLimits, &[0x22; 32]));
        assert!(!table.names(Resource::EntropyAuthority, &[0x11; 32]));
        assert!(!table.names(Resource::ZenohGrants, &[0x33; 32]));
        assert_eq!(table.row(2), Some((Resource::ZenohLimits, [0x11; 32])));
        assert_eq!(table.row(3), None);
    }

    #[test]
    fn an_empty_table_names_no_reader() {
        let bytes = encode_rows(&[]);
        let table = ResourceReaders::decode(&bytes).expect("decodes");
        for resource in Resource::ALL {
            assert!(!table.names(resource, &[0x11; 32]));
        }
    }

    #[test]
    fn unsorted_duplicate_or_zero_rows_fail_closed() {
        for rows in [
            &[(GRANTS, [0x22; 32]), (GRANTS, [0x11; 32])][..],
            &[(LIMITS, [0x11; 32]), (GRANTS, [0x22; 32])][..],
            &[(GRANTS, [0x11; 32]), (GRANTS, [0x11; 32])][..],
            &[(GRANTS, [0x00; 32])][..],
            &[(GRANTS, [0x11; 32]), (LIMITS, [0x00; 32])][..],
        ] {
            assert_eq!(
                ResourceReaders::decode(&encode_rows(rows)).unwrap_err(),
                DecodeError::BadOrder
            );
        }
    }

    #[test]
    fn an_unknown_resource_id_fails_closed() {
        for resource in [0, RESOURCE_BLOCK_RING_AUTHORITY + 1, u32::MAX] {
            assert_eq!(
                ResourceReaders::decode(&encode_rows(&[(resource, [0x11; 32])])).unwrap_err(),
                DecodeError::UnknownResource
            );
        }
    }

    #[test]
    fn wrong_magic_version_flags_and_bounds_fail_closed() {
        let honest = encode_rows(&[(GRANTS, [0x11; 32])]);
        for (position, value, error) in [
            (0, b'X', DecodeError::BadMagic),
            (8, 2, DecodeError::UnsupportedVersion),
            (12, 33, DecodeError::UnsupportedVersion),
            (16, 1, DecodeError::UnknownRequiredFlags),
            (24, 2, DecodeError::BadBounds),
            (28, 0, DecodeError::BadBounds),
        ] {
            let mut bytes = honest.clone();
            bytes[position] = value;
            assert_eq!(ResourceReaders::decode(&bytes).unwrap_err(), error);
        }
        let mut bytes = honest.clone();
        bytes.push(0);
        assert_eq!(
            ResourceReaders::decode(&bytes).unwrap_err(),
            DecodeError::BadBounds
        );
        assert_eq!(
            ResourceReaders::decode(&honest[..HEADER_BYTES - 1]).unwrap_err(),
            DecodeError::Truncated
        );
        let rows = [(GRANTS, [0x11; 32]); MAX_ROWS + 1];
        assert_eq!(
            ResourceReaders::decode(&encode_rows(&rows)).unwrap_err(),
            DecodeError::Truncated
        );
    }

    #[test]
    fn a_full_table_decodes() {
        let mut rows = [(GRANTS, [0u8; 32]); MAX_ROWS];
        for (index, row) in rows.iter_mut().enumerate() {
            row.1 = [index as u8 + 1; 32];
        }
        let bytes = encode_rows(&rows);
        assert_eq!(bytes.len(), MAX_BYTES);
        assert_eq!(
            ResourceReaders::decode(&bytes).unwrap().row_count(),
            MAX_ROWS
        );
    }

    #[test]
    fn identity_is_domain_separated_and_distinguishes_names() {
        for name in ["init", "network-service", ""] {
            assert_ne!(
                reader_identity(name),
                crate::instance_lifetime::instance_identity(name)
            );
        }
        assert_ne!(
            reader_identity("zenoh-service"),
            reader_identity("zenoh-service2")
        );
    }

    #[test]
    fn resource_ids_round_trip_and_are_the_contract_ids() {
        for (index, resource) in Resource::ALL.into_iter().enumerate() {
            assert_eq!(resource.id(), index as u32 + 1);
            assert_eq!(Resource::from_id(resource.id()), Some(resource));
        }
        assert_eq!(Resource::from_id(0), None);
        assert_eq!(Resource::from_id(8), None);
    }
}
