// The reader exam, included into `zenoh_link_limits_v3`. Each `[zenoh-exam] linkv3` line is printed after the assertions of its scenario held, and
// `scripts/lib/zenoh_link_v3_reader_exam.py` judges them.

use std::string::String;

fn line(text: &str) {
    println!("[zenoh-exam] linkv3 {text}");
}

fn changed(edit: impl FnOnce(&mut LinkLimits)) -> LinkLimits {
    let mut limits = SERVICE;
    edit(&mut limits);
    limits
}

fn name(result: Result<(), LimitsError>) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(LimitsError::Stack) => "stack",
        Err(LimitsError::Count) => "count",
        Err(LimitsError::Fixed) => "fixed",
        Err(LimitsError::Heap) => "heap",
        Err(LimitsError::Batch) => "batch",
        Err(LimitsError::Size) => "size",
        Err(LimitsError::Name) => "name",
    }
}

#[test]
fn the_reader_exam() {
    let service = SERVICE;
    let limits = service.lanes.limits;
    let mut config = String::from("config ");
    config.push_str(limits.name);
    config.push_str(match limits.mode {
        Mode::Fixed => " fixed",
        Mode::Heap => " heap",
    });
    for value in [
        limits.batch_bytes as u64,
        limits.payload_bytes,
        limits.key_bytes as u64,
        limits.attachment_bytes as u64,
        limits.max_keys as u64,
        limits.max_subscribers as u64,
        service.local_subscriptions as u64,
        service.lanes.max_runs as u64,
        limits.outstanding_samples as u64,
        limits.stack_bytes,
        limits.reassembly_timeout_ms,
        limits.heap_bytes,
    ] {
        config.push(' ');
        config.push_str(&value.to_string());
    }
    line(&config);
    line(&format!(
        "required {} {}",
        limits.name,
        service.required_stack()
    ));

    let params = service.params();
    line(&format!(
        "params {} {} {} {} {} {} {} {} {}",
        limits.name,
        params.bounds.batch,
        params.announced,
        params.aliases,
        params.per_side,
        params.local,
        params.events,
        params.samples,
        if params.fragments { "heap" } else { "fixed" },
    ));

    let cases: [(&str, LinkLimits); 6] = [
        ("exact", service),
        (
            "stack-under",
            changed(|l| l.lanes.limits.stack_bytes = service.required_stack() - 1),
        ),
        ("zero-local", changed(|l| l.local_subscriptions = 0)),
        ("local-65536", changed(|l| l.local_subscriptions = 65_536)),
        (
            "subscribers-over-keys",
            changed(|l| l.lanes.limits.max_subscribers = 3),
        ),
        ("fixed-with-runs", changed(|l| l.lanes.max_runs = 1)),
    ];
    for (label, candidate) in cases {
        line(&format!("case {label} {}", name(candidate.check())));
    }
}
