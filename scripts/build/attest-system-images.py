#!/usr/bin/env python3

"""Attest system images: record what clean builds of named closures produced, as a git note on HEAD.

    attest-system-images.py --notes-ref REF [--remote REMOTE] --output DIR NAME...
    attest-system-images.py --check --notes-ref REF

The first form attests closures NAME at the checkout's HEAD. Every NAME must be a distinct closure source
that resolves clean. The notes on REF are fetched from REMOTE, each closure is built into DIR/NAME, and one
`contracts/image-attestation/v1` record is written as the note on HEAD under REF and pushed to REMOTE. A
note elsewhere on REF that holds the same derivation id and host class with different output digests is
a mismatch, and nothing is written. A rejected push fetches REF again, compares again, and retries.

The second form decodes every note on REF and refuses a malformed note or a conflicting pair.

Each refusal exits nonzero, writes no note, and ends stderr with `attest-system-images: refused CLASS`.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import image_attestation_contract as CONTRACT
import zutai_cli
from component_sdk import zti
from harness import ROOT
from system_image_closure import resolve_source, source_names, source_path

SCHEMA = ROOT / "contracts" / "image-attestation" / "v1" / "schema.zt"
BUILDER = ROOT / "scripts" / "build" / "build-system-image.py"
OUTPUTS = ("generation", "root", "loader", "image", "identityManifest")
RECORD_FIELDS = {"formatVersion", "commit", "hostClass", "runner", "images"}
HOST_FIELDS = {"devShell", "architecture"}
IMAGE_FIELDS = {"name", "derivationId", *OUTPUTS}
COMMIT = re.compile(rf"[0-9a-f]{{{CONTRACT.COMMIT_BYTES}}}")
DIGEST = re.compile(rf"[0-9a-f]{{{CONTRACT.DIGEST_BYTES}}}")
# The writer's own identity for the notes commits, so a runner with no git configuration can write them.
IDENTITY = ("-c", "user.name=slime-image-attestation", "-c", "user.email=image-attestation@slime-os.invalid")
PUSH_ATTEMPTS = 3


class Refused(Exception):
    """A refusal: `args[0]` is its class, `args[1]` the reason."""


def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["git", *IDENTITY, *arguments], cwd=ROOT, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise Refused("build", f"git {' '.join(arguments)}: {result.stderr.strip()[:300]}")
    return result


def _bounded(value: object, limit: int, *, empty: bool = False) -> bool:
    return isinstance(value, str) and (empty or bool(value)) and len(value.encode("utf-8")) <= limit


def record_problem(raw: object, commit: str) -> str | None:
    """Why the plain projection of a note attached to `commit` breaks the contract's rules, or None."""
    if not isinstance(raw, dict) or set(raw) != RECORD_FIELDS:
        return "its fields are not the attestation's"
    if raw["formatVersion"] != CONTRACT.FORMAT_VERSION:
        return f"its formatVersion is {raw['formatVersion']!r}"
    if not isinstance(raw["commit"], str) or COMMIT.fullmatch(raw["commit"]) is None or raw["commit"] != commit:
        return f"it names commit {raw['commit']!r}, not the commit it is attached to"
    host = raw["hostClass"]
    if not isinstance(host, dict) or set(host) != HOST_FIELDS or not all(
            _bounded(host[field], CONTRACT.MAX_HOST_CLASS_BYTES) for field in HOST_FIELDS):
        return "its host class is malformed"
    if not _bounded(raw["runner"], CONTRACT.MAX_RUNNER_BYTES, empty=True):
        return "its runner is malformed"
    images = raw["images"]
    if not isinstance(images, list) or not 1 <= len(images) <= CONTRACT.MAX_IMAGES:
        return "its image count is out of bounds"
    names = []
    for image in images:
        if not isinstance(image, dict) or set(image) != IMAGE_FIELDS or not _bounded(image["name"], CONTRACT.MAX_NAME_BYTES):
            return "an image entry is malformed"
        if not all(isinstance(image[field], str) and DIGEST.fullmatch(image[field]) for field in ("derivationId", *OUTPUTS)):
            return f"{image['name']} carries a digest that is not lowercase SHA-256"
        names.append(image["name"])
    if names != sorted(names) or len(set(names)) != len(names):
        return "its images are not sorted by name without repeats"
    return None


def read_notes(ref: str) -> dict[str, dict]:
    """Every note on `ref`, keyed by the commit it is attached to, each decoded through the contract.

    A note that does not evaluate, does not decode, or breaks a rule the types cannot state is refused as
    `malformed`: a writer that compared against it would trust an unchecked record.
    """
    listed = git("notes", f"--ref={ref}", "list", check=False)
    if listed.returncode != 0:
        return {}
    commits = [line.split()[1] for line in listed.stdout.splitlines() if line.strip()]
    if not commits:
        return {}
    with tempfile.TemporaryDirectory(prefix="slime-attestations-") as directory:
        root = Path(directory)
        paths = []
        for index, commit in enumerate(commits):
            path = root / f"note-{index}.zti"
            path.write_text(git("notes", f"--ref={ref}", "show", commit).stdout, encoding="utf-8")
            try:
                raw = json.loads(zutai_cli.evaluate("json", path, input_path=path, env_var="SLIME_UNUSED"))
            except (zutai_cli.ZutaiError, json.JSONDecodeError) as error:
                raise Refused("malformed", f"the note on {commit[:12]} does not evaluate: {str(error)[:200]}") from error
            problem = record_problem(raw, commit)
            if problem is not None:
                raise Refused("malformed", f"the note on {commit[:12]}: {problem}")
            paths.append(path)
        # Zutai imports only inside the evaluated file's directory, so the schema is copied beside the entry.
        shutil.copyfile(SCHEMA, root / "schema.zt")
        entries = "".join(f"    s.decodeImageAttestation (loadZti {json.dumps(str(path))});\n" for path in paths)
        (root / "decode.zt").write_text(
            's ::= import "schema.zt";\n'
            "main :: Load -> List (Validation DecodeIssue s.ImageAttestation) ! { load.zti : Path -> Data; }\n"
            "  = load => {\n" + entries + "  };\n"
            "main\n",
            encoding="utf-8",
        )
        result = subprocess.run([str(zutai_cli.binary()), "json", str(root / "decode.zt")], cwd=root,
                                capture_output=True, text=True, env={**os.environ, "ZUTAI_STDLIB_ROOT": str(zutai_cli.STDLIB)})
    if result.returncode != 0:
        raise Refused("malformed", f"the notes do not decode: {(result.stderr or result.stdout).strip()[:300]}")
    decoded = json.loads(result.stdout)
    notes = {}
    for commit, outcome in zip(commits, decoded, strict=True):
        if outcome.get("tag") != "valid":
            raise Refused("malformed", f"the note on {commit[:12]} does not decode through decodeImageAttestation")
        notes[commit] = outcome["payload"]["value"]
    return notes


def host_class() -> dict[str, str]:
    """The default devShell derivation and the machine architecture, as the contract defines the class."""
    try:
        system = subprocess.run(["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
        shell = subprocess.run(["nix", "eval", "--raw", f".#devShells.{system}.default.drvPath"], cwd=ROOT,
                               capture_output=True, text=True, check=True).stdout.strip()
        architecture = subprocess.run(["uname", "-m"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise Refused("build", f"cannot determine the host class: {error}") from error
    host = {"devShell": shell, "architecture": architecture}
    if not all(_bounded(value, CONTRACT.MAX_HOST_CLASS_BYTES) for value in host.values()):
        raise Refused("build", f"the host class {host} is out of the contract's bounds")
    return host


def mismatches(entries: list[dict], host: dict[str, str], notes: dict[str, dict]) -> list[str]:
    """Earlier entries with one of `entries`' derivation ids and the same host class but other digests."""
    found = []
    for commit, record in sorted(notes.items()):
        if record["hostClass"] != host:
            continue
        for image in record["images"]:
            for entry in entries:
                if image["derivationId"] != entry["derivationId"]:
                    continue
                differ = [field for field in OUTPUTS if image[field] != entry[field]]
                if differ:
                    found.append(f"{entry['name']} differs from {image['name']} at {commit[:12]} in {differ}")
    return found


def fetch(remote: str, ref: str) -> None:
    """Make the local `ref` equal to `remote`'s, including when the remote has no such ref yet."""
    result = git("fetch", "--quiet", remote, f"+{ref}:{ref}", check=False)
    if result.returncode == 0:
        return
    if "couldn't find remote ref" in result.stderr:
        git("update-ref", "-d", ref, check=False)
        return
    raise Refused("push", f"cannot fetch {ref} from {remote}: {result.stderr.strip()[:300]}")


def build(name: str, derivation_id: str, output: Path) -> dict:
    destination = output / name
    if destination.exists():
        raise Refused("build", f"{destination} already exists")
    destination.mkdir(parents=True)
    result = subprocess.run([sys.executable, str(BUILDER), str(source_path(name)), str(destination)], cwd=ROOT,
                            capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write("\n".join(result.stdout.strip().splitlines()[-20:]) + "\n")
        raise Refused("build", f"{name} did not build")
    built = json.loads((destination / "build-result.json").read_text(encoding="utf-8"))
    if built.get("dirty") is not False:
        raise Refused("dirty", f"{name} built dirty")
    if built.get("closureIdentity") != derivation_id:
        raise Refused("build", f"{name} built closure {built.get('closureIdentity')}, not {derivation_id}")
    return {"name": name, "derivationId": derivation_id, **{field: built[field]["sha256"] for field in OUTPUTS}}


def attest(ref: str, remote: str | None, output: Path, names: list[str]) -> None:
    known = set(source_names())
    if not names or len(set(names)) != len(names) or len(names) > CONTRACT.MAX_IMAGES:
        raise Refused("closure", "name each closure once, at most "
                                 f"{CONTRACT.MAX_IMAGES} of them")
    unknown = sorted(set(names) - known)
    if unknown:
        raise Refused("closure", f"no closure source named {unknown}")
    if any(not _bounded(name, CONTRACT.MAX_NAME_BYTES) for name in names):
        raise Refused("closure", "a closure name is out of the contract's bounds")
    head = git("rev-parse", "HEAD").stdout.strip()
    if COMMIT.fullmatch(head) is None:
        raise Refused("build", f"HEAD is {head!r}, not a SHA-1 commit id")
    if remote is not None:
        fetch(remote, ref)
    if head in read_notes(ref):
        raise Refused("already-attested", f"{head[:12]} already has a note on {ref}")
    # Every closure resolves clean before anything is built: a dirty build is never attested.
    derivations = {}
    for name in sorted(names):
        materialized = resolve_source(name)
        if materialized.dirty:
            raise Refused("dirty", f"an input of {name} is dirty")
        derivations[name] = materialized.compiled.identity.hex()
    host = host_class()
    # The runner image, informational: GitHub-hosted runners name it in ImageOS and ImageVersion.
    runner = os.environ.get("SLIME_ATTESTATION_RUNNER") or "-".join(
        filter(None, (os.environ.get("ImageOS"), os.environ.get("ImageVersion"))))
    if not _bounded(runner, CONTRACT.MAX_RUNNER_BYTES, empty=True):
        raise Refused("build", f"the runner name {runner!r} is out of the contract's bounds")
    entries = [build(name, derivations[name], output) for name in sorted(names)]
    record = {"formatVersion": CONTRACT.FORMAT_VERSION, "commit": head, "hostClass": host, "runner": runner,
              "images": entries}
    with tempfile.TemporaryDirectory(prefix="slime-attestation-") as directory:
        note = Path(directory) / "note.zti"
        note.write_text(zti(record) + "\n", encoding="utf-8")
        for attempt in range(PUSH_ATTEMPTS):
            notes = read_notes(ref)
            if head in notes:
                raise Refused("already-attested", f"another writer attested {head[:12]} first")
            found = mismatches(entries, host, notes)
            if found:
                raise Refused("mismatch", "; ".join(found))
            # No `-f`: a note that appeared since the last read is never replaced.
            git("notes", f"--ref={ref}", "add", "-F", str(note), head)
            if remote is None:
                break
            pushed = git("push", "--quiet", remote, f"{ref}:{ref}", check=False)
            if pushed.returncode == 0:
                break
            sys.stderr.write(f"attest-system-images: push {attempt + 1} rejected: {pushed.stderr.strip()[:200]}\n")
            fetch(remote, ref)
        else:
            raise Refused("push", f"{ref} was rejected {PUSH_ATTEMPTS} times")
    for entry in entries:
        print(f"attest-system-images: {entry['name']} {entry['derivationId'][:12]} image {entry['image'][:12]}")
    print(f"attest-system-images: attested {len(entries)} closure(s) at {head[:12]} on {ref}")


def check(ref: str) -> None:
    notes = read_notes(ref)
    seen: dict[tuple[str, str, str], tuple[str, tuple[str, ...]]] = {}
    for commit, record in sorted(notes.items()):
        for image in record["images"]:
            key = (image["derivationId"], record["hostClass"]["devShell"], record["hostClass"]["architecture"])
            digests = tuple(image[field] for field in OUTPUTS)
            earlier = seen.setdefault(key, (commit, digests))
            if earlier[1] != digests:
                raise Refused("conflict", f"{image['name']} at {commit[:12]} and the entry at {earlier[0][:12]} "
                                          f"share derivation id {key[0][:12]} and a host class but differ")
    print(f"attest-system-images: {len(notes)} note(s) on {ref} decode and agree")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--notes-ref", required=True, help=f"the notes ref, normally {CONTRACT.NOTES_REF}")
    parser.add_argument("--remote", help="fetch the notes from and push them to this remote")
    parser.add_argument("--output", type=Path, help="the directory each closure is built into")
    parser.add_argument("--check", action="store_true", help="judge the notes on the ref instead of attesting")
    parser.add_argument("names", nargs="*", metavar="NAME")
    arguments = parser.parse_args()
    try:
        if arguments.check:
            if arguments.names or arguments.output or arguments.remote:
                parser.error("--check takes only --notes-ref")
            check(arguments.notes_ref)
        else:
            if arguments.output is None:
                parser.error("--output is required")
            attest(arguments.notes_ref, arguments.remote, arguments.output.resolve(), arguments.names)
    except Refused as refusal:
        sys.stderr.write(f"attest-system-images: {refusal.args[1]}\n")
        sys.stderr.write(f"attest-system-images: refused {refusal.args[0]}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
