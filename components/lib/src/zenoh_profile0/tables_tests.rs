//! Host tests for the slot tables.

use super::*;

#[test]
fn a_table_is_the_size_the_contract_counts() {
    assert_eq!(table_bytes(2, 129), 2 * (129 + 16));
    assert_eq!(table_bytes(65_535, 129), 65_535 * 145);
    // Past the slots a table holds only its count and the padding that count's alignment adds, which
    // the contract's session allowance covers.
    let held = core::mem::size_of::<SlotTable<9, 129>>();
    assert!(held >= table_bytes(9, 129));
    assert!(held - table_bytes(9, 129) < 16, "{held}");
}

#[test]
fn a_slot_holds_its_id_and_key() {
    let mut table = SlotTable::<4, 20>::new();
    let at = table.insert(7, b"demo/key").expect("insert");
    assert_eq!(table.find(7), Some(at));
    assert_eq!(table.get(at), Some((7, &b"demo/key"[..])));
    assert_eq!(table.find(8), None);
    assert_eq!(table.first(), Some((7, &b"demo/key"[..])));
    assert_eq!(table.key_of(7), Some(&b"demo/key"[..]));
    assert_eq!(table.key_of(8), None);
}

fn fill<const N: usize>() {
    let mut table = SlotTable::<N, 8>::new();
    for id in 0..N as u64 {
        table.insert(id + 1, b"k").expect("room");
    }
    assert_eq!(table.len(), N);
    assert_eq!(
        table.insert(N as u64 + 1, b"k"),
        Err(InsertError::Full),
        "{N}"
    );
    for id in 0..N as u64 {
        assert!(table.find(id + 1).is_some(), "{N}: {id}");
    }
}

#[test]
fn the_last_slot_is_taken_and_the_next_is_refused() {
    fill::<1>();
    fill::<4>();
    fill::<9>();
    fill::<255>();
    fill::<256>();
    fill::<257>();
}

#[test]
fn an_id_already_held_is_a_duplicate_and_a_key_past_the_slot_is_refused() {
    let mut table = SlotTable::<4, 4>::new();
    table.insert(1, b"abcd").expect("insert");
    assert_eq!(table.insert(1, b"x"), Err(InsertError::Duplicate));
    assert_eq!(table.insert(2, b"abcde"), Err(InsertError::KeyTooLong));
}

#[test]
fn ids_that_collide_are_each_found_and_removal_leaves_the_chain_intact() {
    let mut table = SlotTable::<4, 4>::new();
    // 1, 5 and 9 all start at slot 1.
    let first = table.insert(1, b"a").expect("1");
    table.insert(5, b"b").expect("5");
    table.insert(9, b"c").expect("9");
    table.remove(first);
    assert_eq!(table.find(1), None);
    assert!(table.find(5).is_some(), "5 is behind the removed slot");
    assert!(table.find(9).is_some(), "9 is behind it too");
    let again = table.insert(13, b"d").expect("reuses the removed slot");
    assert_eq!(again, first);
    assert_eq!(table.find(13), Some(first));
    assert_eq!(table.len(), 3);
}

#[test]
fn a_removed_slot_makes_room_in_a_full_table() {
    let mut table = SlotTable::<3, 4>::new();
    let slots: [usize; 3] =
        core::array::from_fn(|i| table.insert(i as u64 + 1, b"k").expect("room"));
    assert_eq!(table.insert(4, b"k"), Err(InsertError::Full));
    table.remove(slots[1]);
    table.insert(4, b"k").expect("one slot is free");
    assert_eq!(table.insert(5, b"k"), Err(InsertError::Full));
}

#[test]
fn clear_empties_every_slot() {
    let mut table = SlotTable::<5, 4>::new();
    for id in 1..=5 {
        table.insert(id, b"k").expect("room");
    }
    table.clear();
    assert_eq!(table.first(), None);
    assert_eq!(table.find(3), None);
    assert!(table.is_empty());
    table.insert(3, b"k").expect("room again");
}

#[test]
fn ids_use_all_32_bits() {
    let mut table = SlotTable::<5, 4>::new();
    let ids = [0u64, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF, u64::MAX];
    for id in ids {
        table.insert(id, b"k").expect("insert");
    }
    for id in ids {
        let at = table.find(id).expect("found");
        assert_eq!(table.get(at).map(|(held, _)| held), Some(id));
    }
}

#[test]
fn every_slot_of_a_table_of_65535_is_taken_found_and_freed() {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            let mut table = std::boxed::Box::new(SlotTable::<65_535, 16>::new());
            for id in 1..=65_535u64 {
                table.insert(id, &(id as u32).to_le_bytes()).expect("room");
            }
            assert_eq!(table.insert(65_536, b"k"), Err(InsertError::Full));
            for id in [1u64, 255, 256, 257, 32_768, 65_534, 65_535] {
                let at = table.find(id).expect("found");
                assert_eq!(table.get(at), Some((id, &(id as u32).to_le_bytes()[..])));
            }
            for id in 1..=65_535u64 {
                let at = table.find(id).expect("found");
                table.remove(at);
            }
            assert_eq!(table.first(), None);
        })
        .expect("thread")
        .join()
        .expect("table");
}

#[test]
fn a_deferred_removal_is_hidden_until_settled_or_restored() {
    let mut table = SlotTable::<3, 4>::new();
    let a = table.insert(1, b"a").expect("1");
    table.insert(2, b"b").expect("2");
    table.insert(3, b"c").expect("3");
    table.defer_remove(a);
    assert_eq!(table.find(1), None);
    assert_eq!(table.len(), 2);
    assert_eq!(
        table.insert(4, b"d"),
        Err(InsertError::Full),
        "the slot is not reusable yet"
    );
    table.restore(a);
    assert_eq!(table.find(1), Some(a));
    assert_eq!(table.len(), 3);
    table.defer_remove(a);
    table.settle(a);
    assert_eq!(table.insert(4, b"d"), Ok(a));
}

#[test]
fn a_key_is_found_by_its_bytes() {
    let mut table = SlotTable::<4, 8>::new();
    table.insert(9, b"one").expect("1");
    let two = table.insert(10, b"two").expect("2");
    assert_eq!(table.find_key(b"two"), Some(two));
    assert_eq!(table.find_key(b"three"), None);
}

#[test]
fn a_lookup_after_many_removals_still_ends() {
    let mut table = SlotTable::<8, 4>::new();
    for round in 0..40u64 {
        let at = table.insert(round + 1, b"k").expect("room");
        table.remove(at);
    }
    assert_eq!(table.find(999), None);
    assert!(table.is_empty());
}

#[test]
fn a_pending_slot_is_visible_only_to_pending() {
    let mut table = SlotTable::<4, 20>::new();
    let at = table.insert(7, b"demo/key").expect("insert");
    assert_eq!(table.pending(at), None, "a used slot is not pending");
    table.defer_remove(at);
    assert_eq!(table.find(7), None, "a pending slot is out of lookups");
    assert_eq!(table.get(at), None);
    assert_eq!(table.pending(at), Some((7, &b"demo/key"[..])));
    assert_eq!(table.pending(at + 1), None, "an empty slot is not pending");
    assert_eq!(table.pending(99), None, "an index past the table");
    table.restore(at);
    assert_eq!(table.pending(at), None, "a restored slot is used again");
    assert_eq!(table.find(7), Some(at));
    table.defer_remove(at);
    table.settle(at);
    assert_eq!(table.pending(at), None, "a settled slot holds nothing");
}
