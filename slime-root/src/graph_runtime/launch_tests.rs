//! Host tests of the launch's pure decisions, on the generation the
//! production builder wrote for the admission tests: three instances that the
//! root starts, one executable, no binding, no dependency and no optional
//! resource.

use super::*;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use boot_contracts::target_profile::TargetProfile;

const FIXTURE: &[u8] = include_bytes!("../../fixtures/admission-v5.bin");

/// What a test makes of a record: its text.
fn text(record: Record<'_>) -> String {
    format!("{record}")
}

fn admit(generation: &Generation<'_>, target: &str) -> Admission {
    Admission::admit(generation, TargetProfile::by_name(target).unwrap()).unwrap()
}

#[test]
fn plan_of_a_root_instance_carries_what_the_generation_declares() {
    let generation = Generation::decode(FIXTURE).unwrap();
    let admission = admit(&generation, TARGET_PROFILE);
    let mut records = Vec::new();
    let planned = plan_instance(
        &generation,
        &admission,
        1,
        |line| records.push(text(line)),
        text,
    );
    let Ok(Some(plan)) = planned else {
        panic!("the fixture's second instance has no plan");
    };
    assert_eq!(plan.instance.name, "peer-a");
    assert_eq!(plan.executable, "init");
    assert_eq!(
        (plan.cspace_size_bits, plan.priority, plan.threads),
        (7, 254, 1)
    );
    assert_eq!(
        plan.worker_priorities,
        [254; child_vspace::MAX_CHILD_THREADS]
    );
    assert_eq!(
        records,
        [
            format!(
                "SLIME_GRAPH schedule instance=peer-a priority=254 default={}",
                task::CHILD_PRIORITY
            ),
            String::from("SLIME_GRAPH threads instance=peer-a count=1"),
        ]
    );
}

#[test]
fn plan_refuses_an_instance_the_generation_does_not_hold() {
    let generation = Generation::decode(FIXTURE).unwrap();
    let admission = admit(&generation, TARGET_PROFILE);
    let mut records = 0;
    let planned = plan_instance(
        &generation,
        &admission,
        generation.instance_count(),
        |_| records += 1,
        text,
    );
    assert_eq!(
        planned.err().as_deref(),
        Some("SLIME_GRAPH FAIL instance rejected: BadIndex")
    );
    assert_eq!(records, 0);
}

#[test]
fn plan_refuses_an_image_built_for_another_target() {
    let generation = Generation::decode(FIXTURE).unwrap();
    // Admission counts the image as one for another target and admits the
    // generation; the launch is where a root instance must be loadable.
    let admission = admit(&generation, "riscv64-sel4-qemu-virt");
    assert_eq!(admission.loadable, 0);
    let planned = plan_instance(&generation, &admission, 0, |_| {}, text);
    assert_eq!(
        planned.err().as_deref(),
        Some("SLIME_GRAPH FAIL root instance init executable init is not loadable")
    );
}

#[test]
fn root_started_instances_need_no_arena_of_their_own() {
    let generation = Generation::decode(FIXTURE).unwrap();
    for index in 0..generation.instance_count() {
        assert_eq!(image_arena_bits(&generation, index, None, text), Ok(None));
    }
}

#[test]
fn arena_refuses_an_instance_the_generation_does_not_hold() {
    let generation = Generation::decode(FIXTURE).unwrap();
    assert_eq!(
        image_arena_bits(&generation, generation.instance_count(), None, text),
        Err(String::from("image instance rejected: BadIndex"))
    );
}

#[test]
fn a_generation_without_optional_resources_declares_none() {
    let generation = Generation::decode(FIXTURE).unwrap();
    assert!(crate::generation::private_memory_budget_object(&generation).is_none());
    assert!(crate::generation::private_memory_policy_object(&generation).is_none());
    assert!(generation::clock_authority_object(&generation).is_none());
    assert!(wait_set::source_object(&generation).is_none());
    assert!(generation::scheduling_class_object(&generation).is_none());
    assert!(lifecycle::policy_object(&generation).is_none());
    assert!(generation::io_resource_budget_object(&generation).is_none());
    assert!(shared_buffer_budget(&generation).is_none());
    // Authority is never ambient: no budget means no quota.
    assert_eq!(declared_private_memory_pages(None, "init"), 0);
    assert!(declared_quota(None, "init") == HolderQuota::DENY);
}

#[test]
fn an_absent_or_decoded_resource_does_not_stop_the_launch() {
    assert_eq!(admitted(None::<Result<u8, u8>>, "X", text), Ok(None));
    assert_eq!(admitted(Some(Ok::<u8, u8>(7)), "X", text), Ok(Some(7)));
}

#[test]
fn a_resource_that_will_not_decode_is_refused_with_its_record() {
    assert_eq!(
        admitted(
            Some(Err::<u8, u8>(3)),
            "SLIME_MEM FAIL admitted budget",
            text
        ),
        Err(String::from(
            "SLIME_MEM FAIL admitted budget will not decode: 3"
        ))
    );
}
