#!/usr/bin/env python3

"""Judge the image attestation writer and the workflow that runs it.

The expectation lives in `scripts/lib/image_attestation_exam.py`. This script runs the writer, the closure
resolver and nothing else of the product, as commands. The writer must offer:

    python3 scripts/build/attest-system-images.py --notes-ref REF [--remote REMOTE] --output DIR NAME...
        attest closures NAME at the checkout's HEAD: refuse unless every NAME is a distinct closure source
        and resolves clean; fetch REF from REMOTE; build each closure into DIR/NAME; refuse if another
        note on REF has an entry with the same derivation id and host class but different output
        digests; write one `contracts/image-attestation/v1` record as the note on HEAD under REF; push
        REF to REMOTE, and when the push is rejected, fetch again, compare again and retry. It never
        replaces an existing note, and it sets its own git identity.
    python3 scripts/build/attest-system-images.py --check --notes-ref REF
        decode every note on REF and refuse a malformed note or a conflicting pair

Every refusal exits nonzero, writes no note, and ends stderr with `attest-system-images: refused CLASS`.

Steps:

1. The judges' controls hold.
2. In a scratch clone of `HEAD` with its submodules cloned locally, and a bare remote holding none of
   the notes:
   a. The writer attests `sel4-channel` at HEAD while a concurrent writer adds an unrelated note to the
      remote during the first push. The remote then holds both notes. The writer's note decodes, names
      HEAD, the host class this judge computes, the derivation id the resolver reports, and the digests of
      the files the build left in DIR.
   b. A second run at HEAD is refused as `already-attested` and writes no note.
   c. After a commit that changes no input of `sel4-channel`, the derivation id stays the same. Before
      that commit is attested, an unknown or repeated closure is refused as `closure`, and a run with an
      untracked file under `components/lib` as `dirty`. None writes a note, and the dirty run builds
      nothing. The writer then attests the new commit with the same digests, and ignores a note of
      another host class that shares the derivation id with different digests.
   d. After another such commit, a prior note of the same host class and derivation id with a different
      image digest is refused as `mismatch`. So is one a concurrent writer adds during the push, after the
      checkout's notes are made equal to the remote's: the writer must push, see the push rejected, fetch
      the concurrent note and compare again.
   e. `--check` accepts the remote's honest notes, and refuses a conflicting pair as `conflict` and a
      malformed note or a note naming another commit as `malformed`.
3. `.github/workflows/image-attestations.yml` runs the writer nightly and on demand, one run at a time,
   in `nix develop` on `ubuntu-24.04-arm`, for the six sampled closures, pushing
   `refs/notes/image-attestations` to `origin`.

`--controls-only` runs step 1.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import closure_derivation_exam as derivations
import image_attestation_exam as exam
import zutai_cli
from harness import ROOT

SUBMODULES = ("deps/rust-sel4", "deps/zutai")
ZUTAI_BINARY = Path("deps/zutai/target/release/zutai-cli")
GENERATOR = "scripts/generate/generate-system-image-closures.py"
CLOSURE = "sel4-channel"
EDIT = Path("docs/README.md")
UNTRACKED = Path("components/lib/src/image_attestation_exam_untracked.rs")
BUILD_FILES = {
    "generation": "generation/generation.bin", "root": "root.elf", "loader": "loader.elf",
    "image": "image.elf", "identityManifest": "image.identity.json",
}
REF = exam.NOTES_REF
REMOTE = "exam"
IDENTITY = ("-c", "user.name=image-attestation-exam", "-c", "user.email=exam@slime.invalid")
TIMEOUT_SECONDS = 3600


class Findings(list):
    def add(self, step: str, messages: list[str]) -> None:
        self.extend(f"{step}: {message}" for message in messages)


def git(*arguments: str, cwd: Path = ROOT, check: bool = True) -> str:
    result = subprocess.run(["git", *arguments], cwd=cwd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SystemExit(f"image attestations: git {' '.join(arguments)} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def tail(result: subprocess.CompletedProcess[str]) -> str:
    lines = (result.stderr or result.stdout).strip().splitlines()
    return lines[-1][:300] if lines else ""


class Scratch:
    def __init__(self, parent: Path) -> None:
        self.parent = parent
        self.checkout = parent / "checkout"
        self.remote = parent / "remote.git"
        self.home = parent / "gitconfig"
        self.runs = 0

    def writer(self, *arguments: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        """Run the writer with no global or system git configuration; returns the result and its --output."""
        self.runs += 1
        output = self.parent / f"out-{self.runs}"
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_GLOBAL": str(self.home),
                       "GIT_CONFIG_NOSYSTEM": "1"}
        for variable in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "EMAIL"):
            environment.pop(variable, None)
        command = [_sys.executable, exam.WRITER, *arguments]
        if "--check" not in arguments:
            command[2:2] = ["--notes-ref", REF, "--remote", REMOTE, "--output", str(output)]
        result = subprocess.run(command, cwd=self.checkout, capture_output=True, text=True,
                                timeout=TIMEOUT_SECONDS, env=environment)
        return result, output

    def commit(self, message: str) -> str:
        path = self.checkout / EDIT
        path.write_text(path.read_text(encoding="utf-8") + f"\n<!-- {message} -->\n", encoding="utf-8")
        git(*IDENTITY, "commit", "--quiet", "-am", message, cwd=self.checkout)
        return git("rev-parse", "HEAD", cwd=self.checkout).strip()

    def remote_notes(self) -> dict[str, str]:
        listed = git("notes", f"--ref={REF}", "list", cwd=self.remote, check=False)
        notes = {}
        for line in listed.splitlines():
            _, commit = line.split()
            notes[commit] = git("notes", f"--ref={REF}", "show", commit, cwd=self.remote)
        return notes

    def put_note(self, commit: str, text: str, *, where: Path | None = None) -> None:
        note = self.parent / "seed.zti"
        note.write_text(text, encoding="utf-8")
        git(*IDENTITY, "notes", f"--ref={REF}", "add", "-f", "-F", str(note), commit, cwd=where or self.remote)

    def drop_note(self, commit: str, *, where: Path | None = None) -> None:
        git(*IDENTITY, "notes", f"--ref={REF}", "remove", commit, cwd=where or self.remote)

    def arm_race(self, commit: str, text: str) -> Path:
        """On the next push, add `text` as the note on `commit` and reject the push, as a concurrent writer
        that moved the ref first would."""
        note = self.parent / "race.zti"
        note.write_text(text, encoding="utf-8")
        marker = self.parent / "raced"
        marker.unlink(missing_ok=True)
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text(
            "#!/bin/sh\n"
            f'[ -e "{marker}" ] && exit 0\n'
            f'touch "{marker}"\n'
            "env -u GIT_QUARANTINE_PATH -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES "
            f'git -c user.name=race -c user.email=race@slime.invalid notes --ref={REF} add -F "{note}" {commit} >&2 '
            "|| exit 2\n"
            "echo 'image attestation exam: another writer moved the ref' >&2\n"
            "exit 1\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        return marker

    def disarm(self) -> None:
        (self.remote / "hooks" / "pre-receive").unlink(missing_ok=True)


@contextmanager
def scratch() -> Iterator[Scratch]:
    """A clone of `HEAD` with its own refs, its submodules cloned locally at their pins, and a bare remote.

    A clone rather than a worktree: a worktree shares this repository's refs, and the notes the writer and
    this judge write must not reach them.
    """
    parent = Path(tempfile.mkdtemp(prefix="slime-image-attestations-"))
    state = Scratch(parent)
    try:
        state.home.write_text("", encoding="utf-8")
        head = git("rev-parse", "HEAD").strip()
        git("clone", "--quiet", "--shared", "--no-checkout", str(ROOT), str(state.checkout))
        git("checkout", "--quiet", "--detach", head, cwd=state.checkout)
        for submodule in SUBMODULES:
            pin = git("rev-parse", f"HEAD:{submodule}").strip()
            target = state.checkout / submodule
            shutil.rmtree(target, ignore_errors=True)
            git("clone", "--quiet", "--shared", "--no-checkout", str(ROOT / submodule), str(target))
            git("checkout", "--quiet", "--detach", pin, cwd=target)
            if git("rev-parse", "HEAD", cwd=target).strip() != pin:
                raise SystemExit(f"image attestations: the scratch {submodule} is not at its pin")
        (state.checkout / ZUTAI_BINARY).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(zutai_cli.binary(), state.checkout / ZUTAI_BINARY)
        cache = ROOT / "build" / "zutai-cache"
        cache.mkdir(parents=True, exist_ok=True)
        (state.checkout / "build").mkdir(exist_ok=True)
        (state.checkout / "build" / "zutai-cache").symlink_to(cache)
        git("clone", "--quiet", "--bare", "--shared", str(ROOT), str(state.remote))
        for ref in git("for-each-ref", "--format=%(refname)", "refs/notes", cwd=state.remote).split():
            git("update-ref", "-d", ref, cwd=state.remote)
        git("remote", "add", REMOTE, str(state.remote), cwd=state.checkout)
        yield state
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def host_class(checkout: Path) -> tuple[str, str]:
    system = subprocess.run(["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"],
                            cwd=checkout, capture_output=True, text=True, check=True).stdout.strip()
    shell = subprocess.run(["nix", "eval", "--raw", f".#devShells.{system}.default.drvPath"],
                           cwd=checkout, capture_output=True, text=True, check=True).stdout.strip()
    if exam.DEV_SHELL.fullmatch(shell) is None:
        raise SystemExit(f"image attestations: nix printed {shell!r} for the devShell derivation")
    architecture = subprocess.run(["uname", "-m"], capture_output=True, text=True, check=True).stdout.strip()
    return shell, architecture


def derivation_id(checkout: Path, findings: Findings, step: str) -> str | None:
    with tempfile.TemporaryDirectory(prefix="slime-attest-resolve-") as directory:
        output, report = Path(directory) / f"{CLOSURE}.zti", Path(directory) / "report.zti"
        result = subprocess.run([_sys.executable, GENERATOR, "--resolve", CLOSURE, "--output", str(output),
                                 "--report", str(report)], cwd=checkout, capture_output=True, text=True,
                                timeout=TIMEOUT_SECONDS, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if result.returncode != 0 or not report.is_file():
            findings.add(step, [f"--resolve {CLOSURE} exited {result.returncode}: {tail(result)}"])
            return None
        decoded = derivations.decode_record(checkout / derivations.REPORT_SCHEMA, "decodeResolutionReport",
                                            "ResolutionReport", report)
        if decoded.get("dirty") is not False:
            findings.add(step, [f"{CLOSURE} resolves dirty in the scratch clone"])
            return None
        return decoded["derivationId"]


def observed_build(output: Path, identity: str, findings: Findings, step: str) -> dict | None:
    """What this judge observes of the build the writer left in `output`: its derivation id and the digests of
    the files on disk, which the build result must record as well."""
    build = output / CLOSURE
    record = build / "build-result.zti"
    if not record.is_file():
        findings.add(step, [f"the writer left no {CLOSURE}/build-result.zti in --output"])
        return None
    result = derivations.decode_record(ROOT / derivations.CLOSURE_SCHEMA, "decodeSystemImageBuildResult",
                                       "SystemImageBuildResult", record)
    findings.add(step, derivations.build_result_findings(CLOSURE, result, identity, False))
    observed = {"derivationId": identity}
    for field, relative in BUILD_FILES.items():
        path = build / relative
        if not path.is_file():
            findings.add(step, [f"the build left no {relative}"])
            return None
        observed[field] = hashlib.sha256(path.read_bytes()).hexdigest()
        if result[field]["sha256"] != observed[field]:
            findings.add(step, [f"the build result records {field} {result[field]['sha256'][:12]}, "
                                f"the file hashes to {observed[field][:12]}"])
    return observed


def judged_note(state: Scratch, commit: str, findings: Findings, step: str) -> dict | None:
    text = state.remote_notes().get(commit)
    if text is None:
        findings.add(step, [f"the remote holds no note on {commit[:12]}"])
        return None
    try:
        record, raw = exam.decode_note(text, state.parent)
    except ValueError as error:
        findings.add(step, [str(error)])
        return None
    problems = exam.record_findings(record, raw, commit)
    findings.add(step, problems)
    return None if problems else record


def expect_refused(result: subprocess.CompletedProcess[str], wanted: str, findings: Findings, step: str) -> None:
    got = exam.refusal_class(result.stderr)
    if result.returncode == 0 or got != wanted:
        findings.add(step, [f"exit {result.returncode}, refusal {got!r}; expected a nonzero exit refused as {wanted}"])


def foreign(record: dict, commit: str, **changes) -> str:
    changed = json.loads(json.dumps(record))
    changed["commit"] = commit
    for key, value in changes.items():
        if key == "devShell":
            changed["hostClass"]["devShell"] = value
        elif key == "derivationId":
            changed["images"][0]["derivationId"] = value
        else:
            changed["images"][0][key] = value
    return exam.zti(changed) + "\n"


def step_writer(state: Scratch, findings: Findings) -> None:
    if not (state.checkout / exam.WRITER).is_file():
        findings.add("writer", [f"{exam.WRITER} does not exist at HEAD"])
        return
    host = host_class(state.checkout)
    head = git("rev-parse", "HEAD", cwd=state.checkout).strip()
    parents = git("rev-list", "--max-count=4", head, cwd=state.checkout).split()[1:]
    if len(parents) != 3:
        findings.add("writer", ["HEAD has fewer than three ancestors to attach notes to"])
        return
    identity = derivation_id(state.checkout, findings, "writer")
    if identity is None:
        return

    # a. The first attestation, with a concurrent writer moving the remote ref during the push.
    unrelated = exam.honest_record(parents[0], host={"devShell": host[0], "architecture": host[1]}, digest="7")
    unrelated["images"][0]["derivationId"] = "e" * 64
    marker = state.arm_race(parents[0], exam.zti(unrelated) + "\n")
    result, output = state.writer(CLOSURE)
    state.disarm()
    if result.returncode != 0:
        findings.add("attest", [f"the writer exited {result.returncode}: {tail(result)}"])
        return
    if not marker.exists():
        findings.add("attest", ["the writer never pushed to the remote"])
    if parents[0] not in state.remote_notes():
        findings.add("attest", ["the concurrent writer's note did not survive the writer's push"])
    observed = observed_build(output, identity, findings, "attest")
    first = judged_note(state, head, findings, "attest")
    if observed is None or first is None:
        return
    findings.add("attest", exam.observed_findings(first, head, host, {CLOSURE: observed}))

    # b. A second run at an attested commit writes nothing.
    before = state.remote_notes()
    result, _ = state.writer(CLOSURE)
    expect_refused(result, "already-attested", findings, "already-attested")
    if state.remote_notes() != before:
        findings.add("already-attested", ["the refused run changed the remote's notes"])

    # c. Another commit, the same derivation id: the same digests, and another host class not compared.
    second = state.commit("image attestation exam: second commit")
    if derivation_id(state.checkout, findings, "reproduce") != identity:
        findings.add("reproduce", [f"editing {EDIT} moved the derivation id of {CLOSURE}"])
        return

    # Refusals at a commit nothing has attested yet, so no other refusal can come first.
    before = state.remote_notes()
    result, _ = state.writer("sel4-no-such-closure")
    expect_refused(result, "closure", findings, "unknown closure")
    result, _ = state.writer(CLOSURE, CLOSURE)
    expect_refused(result, "closure", findings, "repeated closure")
    untracked = state.checkout / UNTRACKED
    untracked.write_text("// image attestation exam\n", encoding="utf-8")
    try:
        result, output = state.writer(CLOSURE)
    finally:
        untracked.unlink()
    expect_refused(result, "dirty", findings, "dirty")
    if (output / CLOSURE / "build-result.zti").exists():
        findings.add("dirty", ["the writer built a dirty checkout before refusing it"])
    if state.remote_notes() != before:
        findings.add("refusals", ["a refused run changed the remote's notes"])

    state.put_note(parents[1], foreign(first, parents[1], devShell="/nix/store/" + "b" * 32 + "-nix-shell.drv",
                                       image="9" * 64))
    result, output = state.writer(CLOSURE)
    if result.returncode != 0:
        findings.add("reproduce", [f"the writer exited {result.returncode}: {tail(result)}"])
        return
    observed = observed_build(output, identity, findings, "reproduce")
    again = judged_note(state, second, findings, "reproduce")
    if observed is not None and again is not None:
        findings.add("reproduce", exam.observed_findings(again, second, host, {CLOSURE: observed}))
        if again["images"] != first["images"]:
            findings.add("reproduce", ["the second commit's attestation differs from the first's"])

    # d. A conflicting note, before the run and during its push.
    third = state.commit("image attestation exam: third commit")
    state.put_note(parents[2], foreign(first, parents[2], image="9" * 64))
    result, _ = state.writer(CLOSURE)
    expect_refused(result, "mismatch", findings, "mismatch")
    state.drop_note(parents[2])
    # The checkout's notes now equal the remote's, which hold no conflict: only the note the concurrent
    # writer adds during the push can make this run refuse.
    git("fetch", "--quiet", REMOTE, f"+{REF}:{REF}", cwd=state.checkout)
    if parents[2] in git("notes", f"--ref={REF}", "list", cwd=state.checkout):
        findings.add("mismatch during push", ["the checkout still holds the earlier conflicting note"])
    marker = state.arm_race(parents[2], foreign(first, parents[2], root="9" * 64))
    result, _ = state.writer(CLOSURE)
    state.disarm()
    expect_refused(result, "mismatch", findings, "mismatch during push")
    if not marker.exists():
        findings.add("mismatch during push", ["the writer refused without pushing, so the concurrent note was never offered"])
    injected = state.remote_notes().get(parents[2])
    if injected is None:
        findings.add("mismatch during push", ["the concurrent writer's note is not on the remote"])
    else:
        record, _ = exam.decode_note(injected, state.parent)
        if record["images"][0]["root"] != "9" * 64:
            findings.add("mismatch during push", ["the note on the remote is not the concurrent writer's"])
    if third in state.remote_notes():
        findings.add("mismatch", ["a refused run left a note on the remote"])
    if parents[2] in state.remote_notes():
        state.drop_note(parents[2])

    # e. `--check` over the remote's notes.
    git("fetch", "--quiet", REMOTE, f"+{REF}:{REF}", cwd=state.checkout)
    honest = {}
    for commit, text in state.remote_notes().items():
        record, raw = exam.decode_note(text, state.parent)
        findings.add("check", exam.record_findings(record, raw, commit))
        honest[commit] = record
    findings.add("check", exam.conflict_findings(honest))
    result, _ = state.writer("--check", "--notes-ref", REF)
    if result.returncode != 0:
        findings.add("check", [f"--check refused the honest notes: {tail(result)}"])
    for label, text, wanted in (
        ("conflict", foreign(first, parents[2], loader="9" * 64), "conflict"),
        ("malformed", "not an attestation\n", "malformed"),
        ("other commit", foreign(first, head), "malformed"),
    ):
        state.put_note(parents[2], text, where=state.checkout)
        result, _ = state.writer("--check", "--notes-ref", REF)
        expect_refused(result, wanted, findings, f"check ({label})")
        state.drop_note(parents[2], where=state.checkout)
    print(f"image attestations: {state.runs} writer run(s) judged against {len(honest)} remote note(s)")


def step_workflow(findings: Findings) -> None:
    text = git("show", f"HEAD:{exam.WORKFLOW}", check=False)
    if not text:
        findings.add("workflow", [f"{exam.WORKFLOW} does not exist at HEAD"])
        return
    findings.add("workflow", exam.workflow_findings(text))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--controls-only", action="store_true", help="run the judges' controls only")
    arguments = parser.parse_args()
    failed = [label for label, held in exam.controls() if not held]
    if failed:
        print(f"image attestations: FAIL: {len(failed)} control(s) did not hold: {failed}")
        return 1
    print(f"image attestations: {len(exam.controls())} controls held")
    if arguments.controls_only:
        return 0
    if git("status", "--porcelain", "--untracked-files=no").strip():
        print("image attestations: FAIL: commit or stash tracked changes; the exam judges HEAD")
        return 1
    findings = Findings()
    with scratch() as state:
        step_writer(state, findings)
    step_workflow(findings)
    for finding in findings:
        print(f"image attestations: FAIL: {finding}")
    if findings:
        return 1
    print("image attestations: PASS: the writer attests, reproduces, refuses and checks as specified; "
          "the workflow runs it as specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
