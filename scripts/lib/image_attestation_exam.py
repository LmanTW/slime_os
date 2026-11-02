"""The expectation `just image_attestation_check` holds image attestations to.

`scripts/check/check-image-attestations.py` runs the attestation writer and reads what it wrote. The
judgements live here, so the controls can exercise them without a build:

* an attestation note, decoded through `contracts/image-attestation/v1`, against the commit it is
  attached to and the host class and build outputs the judge observed itself;
* the invariant across notes: one derivation id and one host class give one set of output digests;
* the writer's refusal line;
* the workflow that runs the writer.

Every judgement returns findings, and an empty list means it holds.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import yaml

SCHEMA = "contracts/image-attestation/v1/schema.zt"
NOTES_REF = "refs/notes/image-attestations"
WRITER = "scripts/build/attest-system-images.py"
WORKFLOW = ".github/workflows/image-attestations.yml"
RUNNER_LABEL = "ubuntu-24.04-arm"
# The closures the first workflow attests: the closure-derivation exam's sample.
WORKFLOW_CLOSURES = (
    "sel4-call", "sel4-channel", "sel4-io-driver-reset-in-flight", "sel4-private-memory-adaptive-rv64",
    "sel4-private-memory-stress-injected", "sel4-zenoh",
)
REFUSAL = re.compile(r"attest-system-images: refused ([a-z][a-z-]*)")
REFUSAL_CLASSES = ("already-attested", "build", "closure", "conflict", "dirty", "malformed", "mismatch", "push")

FORMAT_VERSION = 1
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_NAME_BYTES = 96
MAX_IMAGES = 128
MAX_HOST_CLASS_BYTES = 256
MAX_RUNNER_BYTES = 128
RECORD_FIELDS = ("commit", "formatVersion", "hostClass", "images", "runner")
HOST_CLASS_FIELDS = ("architecture", "devShell")
OUTPUTS = ("generation", "root", "loader", "image", "identityManifest")
IMAGE_FIELDS = tuple(sorted(("name", "derivationId", *OUTPUTS)))
DEV_SHELL = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+\.drv")


def zti(value: object, indent: int = 0) -> str:
    """`.zti` text for the plain records, lists, texts, integers and booleans these notes hold."""
    pad = "  " * indent
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        if not value:
            return "[]"
        return "[\n" + "".join(f"{pad}  {zti(item, indent + 1)};\n" for item in value) + f"{pad}]"
    if isinstance(value, dict):
        return "{\n" + "".join(f"{pad}  {key} = {zti(item, indent + 1)};\n" for key, item in value.items()) + f"{pad}}}"
    raise TypeError(f"no .zti form for {type(value).__name__}")


def _text(value: object, label: str, limit: int, *, empty: bool = False) -> list[str]:
    if not isinstance(value, str):
        return [f"{label} is not text"]
    size = len(value.encode("utf-8"))
    if size > limit:
        return [f"{label} is {size} bytes, over {limit}"]
    if not value and not empty:
        return [f"{label} is empty"]
    return []


def record_findings(record: dict, raw: dict, commit: str) -> list[str]:
    """Findings for one decoded attestation attached to `commit`. `raw` is the note's plain projection, so a
    field the decoder ignores is still found."""
    findings = []
    if not isinstance(raw, dict) or tuple(sorted(raw)) != RECORD_FIELDS:
        return [f"the note's fields are {sorted(raw) if isinstance(raw, dict) else raw!r}, not {list(RECORD_FIELDS)}"]
    if record.get("formatVersion") != FORMAT_VERSION:
        findings.append(f"formatVersion is {record.get('formatVersion')!r}, not {FORMAT_VERSION}")
    if not isinstance(record.get("commit"), str) or COMMIT.fullmatch(record["commit"]) is None:
        findings.append("commit is not a 40-character lowercase hex id")
    elif record["commit"] != commit:
        findings.append(f"commit names {record['commit'][:12]}, but the note is attached to {commit[:12]}")
    host = raw.get("hostClass")
    if not isinstance(host, dict) or tuple(sorted(host)) != HOST_CLASS_FIELDS:
        findings.append(f"hostClass fields are {sorted(host) if isinstance(host, dict) else host!r}")
    else:
        findings += _text(host["devShell"], "hostClass.devShell", MAX_HOST_CLASS_BYTES)
        findings += _text(host["architecture"], "hostClass.architecture", MAX_HOST_CLASS_BYTES)
    findings += _text(raw.get("runner"), "runner", MAX_RUNNER_BYTES, empty=True)
    images = raw.get("images")
    if not isinstance(images, list) or not 1 <= len(images) <= MAX_IMAGES:
        findings.append(f"images holds {len(images) if isinstance(images, list) else images!r} entries, "
                        f"not 1 to {MAX_IMAGES}")
        return findings
    names = []
    for index, image in enumerate(images):
        label = f"images[{index}]"
        if not isinstance(image, dict) or tuple(sorted(image)) != IMAGE_FIELDS:
            findings.append(f"{label} fields are {sorted(image) if isinstance(image, dict) else image!r}")
            continue
        findings += _text(image["name"], f"{label}.name", MAX_NAME_BYTES)
        names.append(image["name"])
        for field in ("derivationId", *OUTPUTS):
            if not isinstance(image[field], str) or DIGEST.fullmatch(image[field]) is None:
                findings.append(f"{label}.{field} is not a lowercase SHA-256")
    if names != sorted(names) or len(set(names)) != len(names):
        findings.append(f"images are not sorted by name without repeats: {names}")
    return findings


def host_key(record: dict) -> tuple[str, str]:
    host = record["hostClass"]
    return host["devShell"], host["architecture"]


def conflict_findings(notes: dict[str, dict]) -> list[str]:
    """Findings for the invariant across notes, keyed by the commit each note is attached to: one
    derivation id and one host class give one set of output digests."""
    seen: dict[tuple[str, str, str], tuple[str, str, tuple[str, ...]]] = {}
    findings = []
    for commit, record in sorted(notes.items()):
        for image in record["images"]:
            key = (image["derivationId"], *host_key(record))
            digests = tuple(image[field] for field in OUTPUTS)
            earlier = seen.get(key)
            if earlier is None:
                seen[key] = (commit, image["name"], digests)
                continue
            if earlier[2] != digests:
                differ = [field for field, left, right in zip(OUTPUTS, earlier[2], digests, strict=True) if left != right]
                findings.append(f"{image['name']} at {commit[:12]} and {earlier[1]} at {earlier[0][:12]} share "
                                f"derivation id {key[0][:12]} and a host class but differ in {differ}")
    return findings


def observed_findings(record: dict, commit: str, host: tuple[str, str], observed: dict[str, dict]) -> list[str]:
    """Findings for an attestation against what the judge observed itself: the commit, the host class, and
    for each closure its derivation id and the digests of its build outputs."""
    findings = []
    if record.get("commit") != commit:
        findings.append(f"the note names commit {str(record.get('commit'))[:12]}, not {commit[:12]}")
    if host_key(record) != host:
        findings.append(f"the note names host class {host_key(record)}, the judge observed {host}")
    names = [image["name"] for image in record["images"]]
    if names != sorted(observed):
        findings.append(f"the note attests {names}, not {sorted(observed)}")
    for image in record["images"]:
        expected = observed.get(image["name"])
        if expected is None:
            continue
        for field in ("derivationId", *OUTPUTS):
            if image[field] != expected[field]:
                findings.append(f"{image['name']}.{field} is {image[field][:12]}, the judge observed {expected[field][:12]}")
    return findings


def refusal_class(stderr: str) -> str | None:
    """The class the writer's last stderr line refuses with, or None."""
    lines = [line for line in stderr.splitlines() if line.strip()]
    if not lines:
        return None
    match = REFUSAL.fullmatch(lines[-1].strip())
    return match.group(1) if match else None


def _job(document: dict) -> tuple[dict | None, list[str]]:
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or len(jobs) != 1:
        return None, [f"the workflow defines {len(jobs) if isinstance(jobs, dict) else 'no'} jobs, not one"]
    job = next(iter(jobs.values()))
    return (job, []) if isinstance(job, dict) else (None, ["the workflow's job is not a mapping"])


def workflow_findings(text: str) -> list[str]:
    """Findings for the workflow that runs the writer."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        return [f"the workflow is not YAML: {error}"]
    if not isinstance(document, dict):
        return ["the workflow is not a mapping"]
    findings = []
    # YAML 1.1 reads a bare `on` key as true.
    triggers = document.get("on", document.get(True))
    if not isinstance(triggers, dict) or set(triggers) != {"schedule", "workflow_dispatch"}:
        findings.append(f"the workflow's triggers are {sorted(triggers) if isinstance(triggers, dict) else triggers!r}, "
                        "not exactly schedule and workflow_dispatch")
    elif not isinstance(triggers["schedule"], list) or not triggers["schedule"] or not all(
            isinstance(entry, dict) and isinstance(entry.get("cron"), str) for entry in triggers["schedule"]):
        findings.append("the workflow's schedule names no cron entry")
    concurrency = document.get("concurrency")
    if not isinstance(concurrency, dict) or not isinstance(concurrency.get("group"), str) or not concurrency["group"]:
        findings.append("the workflow sets no concurrency group")
    elif "${{" in concurrency["group"]:
        # Every run must land in one group. An expression can name a per-run value, so only a literal
        # group is admitted.
        findings.append(f"the workflow's concurrency group {concurrency['group']!r} is not a literal name")
    elif concurrency.get("cancel-in-progress") is not False:
        findings.append("the workflow's concurrency does not set cancel-in-progress: false")
    if document.get("permissions") != {"contents": "write"}:
        findings.append(f"the workflow's permissions are {document.get('permissions')!r}, not contents: write only")
    job, problems = _job(document)
    findings += problems
    if job is None:
        return findings
    if "permissions" in job:
        findings.append("the job overrides the workflow's permissions")
    for key in ("if", "continue-on-error"):
        if key in job:
            findings.append(f"the job sets {key}, so the writer may not run or may fail unseen")
    if job.get("runs-on") != RUNNER_LABEL:
        findings.append(f"the job runs on {job.get('runs-on')!r}, not {RUNNER_LABEL}")
    if not isinstance(job.get("timeout-minutes"), int):
        findings.append("the job sets no timeout-minutes")
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    checkouts = [step for step in steps if isinstance(step, dict) and str(step.get("uses", "")).startswith("actions/checkout@")]
    if len(checkouts) != 1 or not isinstance(checkouts[0].get("with"), dict) or checkouts[0]["with"].get("submodules") != "recursive":
        findings.append("the job does not check out once with submodules: recursive")
    writers = [step for step in steps if isinstance(step, dict) and WRITER in str(step.get("run", ""))]
    if len(writers) != 1:
        findings.append(f"{len(writers)} steps run {WRITER}, not one")
        return findings
    step = writers[0]
    for key in ("if", "continue-on-error"):
        if key in step:
            findings.append(f"the writer step sets {key}, so the writer may not run or may fail unseen")
    if step.get("shell", "bash") != "bash":
        findings.append(f"the writer step runs in shell {step.get('shell')!r}, not bash")
    command = str(step["run"]).replace("\\\n", " ").strip()
    # The step must be exactly one writer invocation: nothing before it, no second command, no operator
    # that could skip it or hide its exit status.
    if "\n" in command or any(token in command for token in (";", "&", "|", "<", ">", "#", "`", "$(")):
        findings.append("the writer step is not exactly one command")
        return findings
    words = command.split()
    prefix = ["nix", "develop", "--command", "python3", WRITER]
    if words[:len(prefix)] != prefix:
        findings.append(f"the writer step does not start with `{' '.join(prefix)}`")
        return findings
    arguments = words[len(prefix):]
    options: dict[str, str] = {}
    names: list[str] = []
    index = 0
    while index < len(arguments):
        word = arguments[index]
        if word.startswith("--"):
            if index + 1 >= len(arguments):
                findings.append(f"the writer option {word} has no value")
                break
            options[word] = arguments[index + 1]
            index += 2
        else:
            names.append(word)
            index += 1
    if options.get("--notes-ref") != NOTES_REF:
        findings.append(f"the writer step's --notes-ref is {options.get('--notes-ref')!r}, not {NOTES_REF}")
    if options.get("--remote") != "origin":
        findings.append(f"the writer step's --remote is {options.get('--remote')!r}, not origin")
    if "--output" not in options:
        findings.append("the writer step passes no --output")
    if set(options) - {"--notes-ref", "--remote", "--output"}:
        findings.append(f"the writer step passes unexpected options {sorted(set(options) - {'--notes-ref', '--remote', '--output'})}")
    if sorted(names) != list(WORKFLOW_CLOSURES) or len(set(names)) != len(names):
        findings.append(f"the writer step attests {names}, not {list(WORKFLOW_CLOSURES)}")
    return findings


# ---------------------------------------------------------------------------------------------------------
# Controls: each judgement refuses a crafted defect and accepts its honest counterpart.

HONEST_HOST = {"devShell": "/nix/store/" + "a" * 32 + "-nix-shell.drv", "architecture": "aarch64"}
HONEST_COMMIT = "1" * 40


def honest_record(commit: str = HONEST_COMMIT, *, host: dict | None = None, digest: str = "c") -> dict:
    image = {"name": "sel4-channel", "derivationId": "d" * 64, **{field: digest * 64 for field in OUTPUTS}}
    return {
        "formatVersion": FORMAT_VERSION, "commit": commit, "hostClass": dict(host or HONEST_HOST),
        "runner": "ubuntu24-20261101", "images": [image],
    }


def _mutated(change) -> dict:
    record = json.loads(json.dumps(honest_record()))
    change(record)
    return record


def _record_controls() -> Iterator[tuple[str, bool]]:
    yield "record-honest", not record_findings(honest_record(), honest_record(), HONEST_COMMIT)
    second = {"name": "sel4-zenoh", "derivationId": "e" * 64, **{field: "f" * 64 for field in OUTPUTS}}
    cases = {
        "record-extra-field": lambda r: r.update(signature="x"),
        "record-missing-runner": lambda r: r.pop("runner"),
        "record-version": lambda r: r.update(formatVersion=2),
        "record-commit-short": lambda r: r.update(commit="1" * 39),
        "record-commit-upper": lambda r: r.update(commit="A" * 40),
        "record-commit-other": lambda r: r.update(commit="2" * 40),
        "record-host-extra": lambda r: r["hostClass"].update(kernel="6.8"),
        "record-host-empty-devshell": lambda r: r["hostClass"].update(devShell=""),
        "record-host-empty-architecture": lambda r: r["hostClass"].update(architecture=""),
        "record-host-long": lambda r: r["hostClass"].update(devShell="x" * (MAX_HOST_CLASS_BYTES + 1)),
        "record-runner-long": lambda r: r.update(runner="r" * (MAX_RUNNER_BYTES + 1)),
        "record-no-images": lambda r: r.update(images=[]),
        "record-too-many-images": lambda r: r.update(images=[
            {**r["images"][0], "name": f"sel4-{index:03d}"} for index in range(MAX_IMAGES + 1)]),
        "record-image-extra": lambda r: r["images"][0].update(bytes=1),
        "record-image-missing-loader": lambda r: r["images"][0].pop("loader"),
        "record-image-empty-name": lambda r: r["images"][0].update(name=""),
        "record-image-long-name": lambda r: r["images"][0].update(name="n" * (MAX_NAME_BYTES + 1)),
        "record-image-bad-derivation": lambda r: r["images"][0].update(derivationId="d" * 63),
        "record-image-upper-digest": lambda r: r["images"][0].update(image="C" * 64),
        "record-unsorted": lambda r: r.update(images=[second, r["images"][0]]),
        "record-repeated": lambda r: r.update(images=[r["images"][0], dict(r["images"][0])]),
    }
    for label, change in cases.items():
        record = _mutated(change)
        yield label, bool(record_findings(record, record, HONEST_COMMIT))
    sorted_pair = _mutated(lambda r: r.update(images=[r["images"][0], second]))
    yield "record-two-sorted", not record_findings(sorted_pair, sorted_pair, HONEST_COMMIT)
    empty_runner = _mutated(lambda r: r.update(runner=""))
    yield "record-empty-runner", not record_findings(empty_runner, empty_runner, HONEST_COMMIT)


def _conflict_controls() -> Iterator[tuple[str, bool]]:
    first, second = "1" * 40, "2" * 40
    other_host = {**HONEST_HOST, "devShell": "/nix/store/" + "b" * 32 + "-nix-shell.drv"}
    other_arch = {**HONEST_HOST, "architecture": "x86_64"}
    yield "conflict-identical", not conflict_findings({first: honest_record(first), second: honest_record(second)})
    for field in OUTPUTS:
        later = honest_record(second)
        later["images"][0][field] = "9" * 64
        yield f"conflict-{field}", bool(conflict_findings({first: honest_record(first), second: later}))
    yield "conflict-other-devshell", not conflict_findings(
        {first: honest_record(first), second: honest_record(second, host=other_host, digest="9")})
    yield "conflict-other-architecture", not conflict_findings(
        {first: honest_record(first), second: honest_record(second, host=other_arch, digest="9")})
    other_id = honest_record(second, digest="9")
    other_id["images"][0]["derivationId"] = "e" * 64
    yield "conflict-other-derivation", not conflict_findings({first: honest_record(first), second: other_id})
    third = honest_record("3" * 40)
    third["images"][0]["image"] = "9" * 64
    yield "conflict-third-note", bool(conflict_findings(
        {first: honest_record(first), second: honest_record(second), "3" * 40: third}))


def _observed_controls() -> Iterator[tuple[str, bool]]:
    record = honest_record()
    host = (HONEST_HOST["devShell"], HONEST_HOST["architecture"])
    observed = {"sel4-channel": {"derivationId": "d" * 64, **{field: "c" * 64 for field in OUTPUTS}}}
    yield "observed-honest", not observed_findings(record, HONEST_COMMIT, host, observed)
    yield "observed-commit", bool(observed_findings(record, "2" * 40, host, observed))
    yield "observed-host", bool(observed_findings(record, HONEST_COMMIT, (host[0], "x86_64"), observed))
    yield "observed-missing-image", bool(observed_findings(record, HONEST_COMMIT, host, {**observed, "sel4-zenoh": observed["sel4-channel"]}))
    for field in ("derivationId", *OUTPUTS):
        changed = {"sel4-channel": {**observed["sel4-channel"], field: "9" * 64}}
        yield f"observed-{field}", bool(observed_findings(record, HONEST_COMMIT, host, changed))


def _refusal_controls() -> Iterator[tuple[str, bool]]:
    yield "refusal-honest", refusal_class("building\nattest-system-images: refused mismatch\n") == "mismatch"
    yield "refusal-not-last", refusal_class("attest-system-images: refused mismatch\ndone\n") is None
    yield "refusal-other-tool", refusal_class("convert-mcap: refused mismatch\n") is None
    yield "refusal-empty", refusal_class("") is None
    yield "refusal-trailing-text", refusal_class("attest-system-images: refused mismatch now\n") is None


HONEST_WORKFLOW = f"""\
name: Image attestations
on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:
concurrency:
  group: image-attestations
  cancel-in-progress: false
permissions:
  contents: write
jobs:
  attest:
    runs-on: {RUNNER_LABEL}
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v7
        with:
          submodules: recursive
      - run: >
          nix develop --command python3 {WRITER}
          --notes-ref {NOTES_REF} --remote origin --output "$RUNNER_TEMP/attest"
          {' '.join(WORKFLOW_CLOSURES)}
"""


def _workflow_controls() -> Iterator[tuple[str, bool]]:
    yield "workflow-honest", not workflow_findings(HONEST_WORKFLOW)
    base = yaml.safe_load(HONEST_WORKFLOW)

    def variant(change) -> str:
        document = json.loads(json.dumps(base, default=str).replace('"true":', '"on":'))
        change(document)
        return yaml.safe_dump(document, sort_keys=False)

    yield "workflow-roundtrip", not workflow_findings(variant(lambda d: None))
    job = lambda d: d["jobs"]["attest"]  # noqa: E731
    writer = lambda d: job(d)["steps"][1]  # noqa: E731
    cases = {
        "workflow-push-trigger": lambda d: d["on"].update(push={"branches": ["main"]}),
        "workflow-no-dispatch": lambda d: d["on"].pop("workflow_dispatch"),
        "workflow-no-schedule": lambda d: d["on"].pop("schedule"),
        "workflow-empty-schedule": lambda d: d["on"].update(schedule=[]),
        "workflow-no-concurrency": lambda d: d.pop("concurrency"),
        "workflow-cancels": lambda d: d["concurrency"].update({"cancel-in-progress": True}),
        "workflow-cancel-unset": lambda d: d["concurrency"].pop("cancel-in-progress"),
        "workflow-broad-permissions": lambda d: d["permissions"].update({"pull-requests": "write"}),
        "workflow-read-permissions": lambda d: d.update(permissions={"contents": "read"}),
        "workflow-job-permissions": lambda d: job(d).update(permissions={"contents": "read"}),
        "workflow-second-job": lambda d: d["jobs"].update(other={"runs-on": RUNNER_LABEL, "steps": []}),
        "workflow-runner": lambda d: job(d).update({"runs-on": "ubuntu-latest"}),
        "workflow-no-timeout": lambda d: job(d).pop("timeout-minutes"),
        "workflow-no-submodules": lambda d: job(d)["steps"][0].pop("with"),
        "workflow-no-writer": lambda d: job(d)["steps"].pop(1),
        "workflow-two-writers": lambda d: job(d)["steps"].append(dict(writer(d))),
        "workflow-outside-nix": lambda d: writer(d).update(run=writer(d)["run"].replace("nix develop --command ", "")),
        "workflow-other-ref": lambda d: writer(d).update(run=writer(d)["run"].replace(NOTES_REF, "refs/notes/other")),
        "workflow-other-remote": lambda d: writer(d).update(run=writer(d)["run"].replace("--remote origin", "--remote fork")),
        "workflow-no-output": lambda d: writer(d).update(run=re.sub(r'--output \S+ ', "", writer(d)["run"])),
        "workflow-extra-option": lambda d: writer(d).update(run=writer(d)["run"].replace("--remote origin", "--remote origin --force yes")),
        "workflow-missing-closure": lambda d: writer(d).update(run=writer(d)["run"].replace(" sel4-zenoh", "")),
        "workflow-extra-closure": lambda d: writer(d).update(run=writer(d)["run"].rstrip() + " sel4-boot\n"),
        "workflow-repeated-closure": lambda d: writer(d).update(run=writer(d)["run"].replace("sel4-zenoh", "sel4-channel")),
        "workflow-run-id-group": lambda d: d["concurrency"].update(group="image-attestations-${{ github.run_id }}"),
        "workflow-expression-group": lambda d: d["concurrency"].update(group="${{ github.workflow }}"),
        "workflow-echo": lambda d: writer(d).update(run="echo " + writer(d)["run"]),
        "workflow-prefixed-command": lambda d: writer(d).update(run="true && " + writer(d)["run"]),
        "workflow-or-true": lambda d: writer(d).update(run=writer(d)["run"].rstrip() + " || true\n"),
        "workflow-second-command": lambda d: writer(d).update(run=writer(d)["run"].rstrip() + "; exit 0\n"),
        "workflow-second-line": lambda d: writer(d).update(run=writer(d)["run"].rstrip() + "\nexit 0\n"),
        "workflow-comment": lambda d: writer(d).update(run="# " + writer(d)["run"]),
        "workflow-pipe": lambda d: writer(d).update(run=writer(d)["run"].rstrip() + " | tee log\n"),
        "workflow-step-if": lambda d: writer(d).update({"if": False}),
        "workflow-step-continue": lambda d: writer(d).update({"continue-on-error": True}),
        "workflow-step-shell": lambda d: writer(d).update(shell="sh -c 'exit 0' {0}"),
        "workflow-job-if": lambda d: job(d).update({"if": False}),
        "workflow-job-continue": lambda d: job(d).update({"continue-on-error": True}),
    }
    for label, change in cases.items():
        yield label, bool(workflow_findings(variant(change)))
    yield "workflow-not-yaml", bool(workflow_findings("on: [\n"))


def controls() -> list[tuple[str, bool]]:
    """Each control and whether it held."""
    return [*_record_controls(), *_conflict_controls(), *_observed_controls(), *_refusal_controls(),
            *_workflow_controls()]


def decode_note(text: str, directory: Path) -> tuple[dict, dict]:
    """A note's decoded record and its plain projection. Raises ValueError when the note does not decode
    through `decodeImageAttestation`."""
    import zutai_cli
    from closure_derivation_exam import decode_record

    from harness import ROOT

    path = directory / "note.zti"
    path.write_text(text, encoding="utf-8")
    record = decode_record(ROOT / SCHEMA, "decodeImageAttestation", "ImageAttestation", path)
    try:
        raw = json.loads(zutai_cli.evaluate("json", path, input_path=path, env_var="SLIME_UNUSED"))
    except Exception as error:  # noqa: BLE001 - a note that evaluates differently is malformed
        raise ValueError(f"the note has no plain projection: {error}") from error
    return record, raw
