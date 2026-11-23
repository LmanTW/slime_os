use super::{Admission, GenerationError};
use alloc::vec::Vec;
use boot_contracts::generation::{self as wire, DecodeError, Generation};
use boot_contracts::target_profile::TargetProfile;

fn fixture() -> Vec<u8> {
    include_bytes!("../../fixtures/admission-v5.bin").to_vec()
}

fn read_offset(bytes: &[u8], at: usize) -> usize {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize
}

fn write_u64(bytes: &mut [u8], at: usize, value: usize) {
    bytes[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

fn authenticate(bytes: &mut [u8]) {
    let identity = wire::generation_identity(bytes);
    bytes[wire::OFF_HEADER_IDENTITY..wire::OFF_HEADER_IDENTITY + identity.len()]
        .copy_from_slice(&identity);
}

fn quotas(bytes: &mut [u8], pages: [u32; 3]) {
    let start = read_offset(bytes, wire::OFF_HEADER_RESOURCE_QUOTA_OFFSET);
    for (index, pages) in pages.into_iter().enumerate() {
        let at = start + index * wire::RESOURCE_QUOTA_LEN + wire::OFF_RESOURCE_QUOTA_FRAME_COUNT;
        bytes[at..at + 4].copy_from_slice(&pages.to_le_bytes());
    }
    authenticate(bytes);
}

fn admit(bytes: &[u8], target: &str) -> Result<Admission, GenerationError> {
    let generation = Generation::decode(bytes)?;
    Admission::admit(&generation, TargetProfile::by_name(target).unwrap())
}

#[test]
fn large_image_quota_above_ceiling_refused() {
    let mut bytes = fixture();
    let target = "aarch64-sel4-qemu-virt";
    admit(&bytes, target).expect("unmodified production-built fixture");
    quotas(&mut bytes, [2, 3, 3]);
    assert!(matches!(
        admit(&bytes, target),
        Err(GenerationError::ImageQuotaTooSmall {
            declared: 2,
            required: 3,
            ..
        })
    ));
    quotas(&mut bytes, [32768, 3, 3]);
    admit(&bytes, target).expect("exact per-image ceiling");
    quotas(&mut bytes, [32769, 3, 3]);
    assert!(matches!(
        admit(&bytes, target),
        Err(GenerationError::QuotaExceedsCeiling {
            kind: "frame",
            declared: 32769,
            limit: 32768,
            ..
        })
    ));
    quotas(&mut bytes, [512, 2, 2]);
    let conservative = "aarch64-rpi5";
    admit(&bytes, conservative).expect("conservative ceiling");
    quotas(&mut bytes, [513, 2, 2]);
    assert!(matches!(
        admit(&bytes, conservative),
        Err(GenerationError::QuotaExceedsCeiling {
            kind: "frame",
            declared: 513,
            limit: 512,
            ..
        })
    ));
}

#[test]
fn large_image_aggregate_above_ceiling_refused() {
    let mut bytes = fixture();
    let target = "aarch64-sel4-qemu-virt";
    quotas(&mut bytes, [32768, 32765, 3]);
    admit(&bytes, target).expect("exact aggregate ceiling");
    quotas(&mut bytes, [32768, 32766, 3]);
    assert!(matches!(
        admit(&bytes, target),
        Err(GenerationError::ImagePlanExceedsCeiling {
            declared: 65537,
            limit: 65536,
        })
    ));
}

#[test]
fn generation_object_above_bound_refused() {
    assert_eq!(wire::MAX_OBJECT_PAYLOAD_BYTES, 128 * 1024 * 1024);
    let mut bytes = fixture();
    let object = read_offset(&bytes, wire::OFF_HEADER_OBJECT_OFFSET);
    let payload = read_offset(&bytes, object + wire::OFF_OBJECT_PAYLOAD_OFFSET);
    bytes.resize(payload + wire::MAX_OBJECT_PAYLOAD_BYTES, 0);
    write_u64(
        &mut bytes,
        object + wire::OFF_OBJECT_PAYLOAD_LEN,
        wire::MAX_OBJECT_PAYLOAD_BYTES,
    );
    let mut hasher = boot_contracts::sha256::Sha256::new();
    hasher.update(&bytes[payload..]);
    bytes[object + wire::OFF_OBJECT_DIGEST..object + wire::OFF_OBJECT_DIGEST + 32]
        .copy_from_slice(&hasher.finalize());
    let total = bytes.len();
    write_u64(&mut bytes, wire::OFF_HEADER_TOTAL_LEN, total);
    authenticate(&mut bytes);
    admit(&bytes, "aarch64-sel4-qemu-virt").expect("exact object byte ceiling");
    bytes.push(0);
    write_u64(
        &mut bytes,
        object + wire::OFF_OBJECT_PAYLOAD_LEN,
        wire::MAX_OBJECT_PAYLOAD_BYTES + 1,
    );
    authenticate_object(&mut bytes, object);
    let total = bytes.len();
    write_u64(&mut bytes, wire::OFF_HEADER_TOTAL_LEN, total);
    authenticate(&mut bytes);
    assert!(matches!(
        Generation::decode(&bytes),
        Err(DecodeError::BadBounds)
    ));
}

fn authenticate_object(bytes: &mut [u8], object: usize) {
    let payload = read_offset(bytes, object + wire::OFF_OBJECT_PAYLOAD_OFFSET);
    let len = read_offset(bytes, object + wire::OFF_OBJECT_PAYLOAD_LEN);
    let mut hasher = boot_contracts::sha256::Sha256::new();
    hasher.update(&bytes[payload..payload + len]);
    bytes[object + wire::OFF_OBJECT_DIGEST..object + wire::OFF_OBJECT_DIGEST + 32]
        .copy_from_slice(&hasher.finalize());
}

#[test]
fn generation_above_bound_refused() {
    assert_eq!(wire::MAX_GENERATION_BYTES, 256 * 1024 * 1024);
    let mut bytes = include_bytes!("../../fixtures/admission-bounds-v5.bin").to_vec();
    admit(&bytes, "aarch64-sel4-qemu-virt").expect("valid baseline");
    let first = read_offset(&bytes, wire::OFF_HEADER_OBJECT_OFFSET) + wire::OBJECT_LEN;
    let second = first + wire::OBJECT_LEN;
    let payload = read_offset(&bytes, first + wire::OFF_OBJECT_PAYLOAD_OFFSET);
    let second_payload = payload + wire::MAX_OBJECT_PAYLOAD_BYTES;
    bytes.resize(wire::MAX_GENERATION_BYTES, 0);
    write_u64(
        &mut bytes,
        first + wire::OFF_OBJECT_PAYLOAD_LEN,
        wire::MAX_OBJECT_PAYLOAD_BYTES,
    );
    write_u64(
        &mut bytes,
        second + wire::OFF_OBJECT_PAYLOAD_OFFSET,
        second_payload,
    );
    let second_len = bytes.len() - second_payload;
    assert!(second_len + 1 <= wire::MAX_OBJECT_PAYLOAD_BYTES);
    write_u64(
        &mut bytes,
        second + wire::OFF_OBJECT_PAYLOAD_LEN,
        second_len,
    );
    authenticate_object(&mut bytes, first);
    authenticate_object(&mut bytes, second);
    let total = bytes.len();
    write_u64(&mut bytes, wire::OFF_HEADER_TOTAL_LEN, total);
    authenticate(&mut bytes);
    admit(&bytes, "aarch64-sel4-qemu-virt").expect("exact generation byte ceiling");
    bytes.push(0);
    write_u64(
        &mut bytes,
        second + wire::OFF_OBJECT_PAYLOAD_LEN,
        second_len + 1,
    );
    authenticate_object(&mut bytes, second);
    let total = bytes.len();
    write_u64(&mut bytes, wire::OFF_HEADER_TOTAL_LEN, total);
    authenticate(&mut bytes);
    assert!(matches!(
        Generation::decode(&bytes),
        Err(DecodeError::BadBounds)
    ));
}

/// Admission reaches the reader table: a row for an instance the generation
/// declares is admitted, and the same row for an undeclared name is refused.
#[test]
fn a_reader_row_for_an_undeclared_instance_is_refused() {
    use boot_contracts::resource_reader::{HEADER_BYTES, MAGIC, reader_identity};
    let mut bytes = include_bytes!("../../fixtures/admission-readers-v5.bin").to_vec();
    admit(&bytes, "aarch64-sel4-qemu-virt").expect("the builder's reader table");

    let objects = read_offset(&bytes, wire::OFF_HEADER_OBJECT_OFFSET);
    let count = u32::from_le_bytes(
        bytes[wire::OFF_HEADER_OBJECT_COUNT..wire::OFF_HEADER_OBJECT_COUNT + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let (object, payload) = (0..count)
        .map(|index| objects + index * wire::OBJECT_LEN)
        .map(|object| {
            (
                object,
                read_offset(&bytes, object + wire::OFF_OBJECT_PAYLOAD_OFFSET),
            )
        })
        .find(|(_, payload)| bytes[*payload..].starts_with(&MAGIC))
        .expect("the fixture carries a reader table");
    // The first row's identity follows its 4-byte table id.
    let identity = payload + HEADER_BYTES + 4;
    assert_eq!(
        bytes[identity..identity + 32],
        reader_identity("entropy-service")
    );
    bytes[identity..identity + 32].copy_from_slice(&reader_identity("no-such-instance"));
    authenticate_object(&mut bytes, object);
    authenticate(&mut bytes);
    assert_eq!(
        admit(&bytes, "aarch64-sel4-qemu-virt").err(),
        Some(GenerationError::UnsatisfiableResourceReaders)
    );
}
