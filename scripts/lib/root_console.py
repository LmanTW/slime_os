"""Judge for the root's own console UART on QEMU `virt`.

The root of every `aarch64-sel4-qemu-virt` image maps the machine's PL011 and
installs it as the sink of `slime-root/src/diagnostic.rs`. From then on the
root writes each record's bytes to the UART's registers, and the kernel's debug
console receives none. Three judges hold the product to that:

* `run_exam` compiles the actual `diagnostic.rs` on the host against a register
  page and a counting kernel sink. It is the judge of the route: the bytes on a
  serial line are the same whichever route wrote them, so no boot can tell the
  two apart.
* `audit` reads the root's sources. It holds the one install call to
  `main.rs`, before a record of `main` itself, and the build script to the one
  target profile.
* `judge` reads the raw serial bytes of one boot. The install marker names
  QEMU's PL011, only records of the allocator's bring-up precede it, and every
  line feed after it follows a carriage return. The root writes that carriage
  return itself once the kernel no longer does.

The root can map a device page only after its allocator and its metadata exist,
and that bring-up prints records of its own. Those still go to the kernel sink.
`judge` counts them, and refuses any other record before the marker.

`controls` runs the negative controls of all three. Standard library only.
"""

from __future__ import annotations

import dataclasses
import re
import subprocess
import tempfile
from pathlib import Path


# QEMU's `virt` machine places its first PL011 here (`VIRT_UART0` in
# hw/arm/virt.c). The judge takes the address from the machine, not from the
# root's sources.
QEMU_VIRT_PL011 = 0x0900_0000
PROFILE = "aarch64-sel4-qemu-virt"
CONFIGURATION = "slime_root_console_pl011"
MARKER = re.compile(rb"SLIME_ROOT console uart=(\S+) paddr=(\S+)")
RECORD = re.compile(rb"\[[a-z0-9-]+\] |SLIME_[A-Z0-9]+ ")
# The record families `slime-root/src/object_allocator.rs` prints while the
# allocator, the root CSpace and the metadata come up.
BRING_UP = re.compile(rb"SLIME_BACKING |SLIME_ALLOC |SLIME_ROOT (?:infrastructure|cspace|metadata) ")
ANSI = re.compile(rb"\x1b\[[0-9;]*m")
DIAGNOSTIC = "slime-root/src/diagnostic.rs"
BINARY = "slime-root/src/main.rs"
BUILD = "slime-root/build.rs"
DEVICE = "slime-root/src/device.rs"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"root console: {message}")


_RAW_STRING = re.compile(r'(?:br|cr|r)(#*)"')
_STRING = re.compile(r'(?:b|c)?"(?:[^"\\]|\\.)*"', re.DOTALL)
_CHARACTER = re.compile(r"(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")


def _code(text: str) -> str:
    """Blank Rust comments and keep everything else, literals included.

    The audit reads character and string literals, so it cannot use the
    literal-masking reader of `console_record_controls`. Offsets and line
    numbers are those of `text`.
    """
    output: list[str] = []
    cursor = 0
    while cursor < len(text):
        start = cursor
        if text.startswith("//", cursor):
            end = text.find("\n", cursor)
            cursor = len(text) if end < 0 else end
        elif text.startswith("/*", cursor):
            cursor += 2
            depth = 1
            while cursor < len(text) and depth:
                if text.startswith("/*", cursor):
                    depth, cursor = depth + 1, cursor + 2
                elif text.startswith("*/", cursor):
                    depth, cursor = depth - 1, cursor + 2
                else:
                    cursor += 1
            require(depth == 0, "unterminated Rust block comment")
        else:
            raw = _RAW_STRING.match(text, cursor)
            literal = _STRING.match(text, cursor) or _CHARACTER.match(text, cursor)
            if raw:
                terminator = '"' + raw.group(1)
                end = text.find(terminator, raw.end())
                require(end >= 0, "unterminated Rust raw string")
                cursor = end + len(terminator)
            elif literal:
                cursor = literal.end()
            else:
                cursor += 1
            output.append(text[start:cursor])
            continue
        output.append("".join("\n" if char == "\n" else " " for char in text[start:cursor]))
    return "".join(output)


# ---- the raw serial bytes of one boot ----


@dataclasses.dataclass(frozen=True)
class Verdict:
    early: int
    records: int
    line_feeds: int

    def line(self) -> str:
        return (
            f"[root-console] marker uart=pl011 paddr={QEMU_VIRT_PL011:#x} "
            f"bring_up_records_before_marker={self.early} "
            f"records_after_marker={self.records} line_feeds_after_marker={self.line_feeds}"
        )


def judge(raw: bytes) -> Verdict:
    """Raise ValueError unless `raw` shows one install marker after nothing but
    bring-up records, and a carriage return before every later line feed."""
    lines = raw.split(b"\n")
    require(len(lines) > 1, "the capture holds no complete line")
    complete, tail = lines[:-1], lines[-1]
    texts = [ANSI.sub(b"", line.removesuffix(b"\r")) for line in complete]
    marked = [index for index, text in enumerate(texts) if MARKER.search(text)]
    require(len(marked) == 1, f"expected exactly one install marker, found {len(marked)}")
    position = marked[0]
    found = MARKER.fullmatch(texts[position])
    require(found is not None, f"the install marker shares its line: {texts[position]!r}")
    require(found.group(1) == b"pl011", f"the marker names UART kind {found.group(1)!r}, not pl011")
    try:
        address = int(found.group(2), 16)
    except ValueError:
        address = -1
    require(
        found.group(2).startswith(b"0x") and address == QEMU_VIRT_PL011,
        f"the marker names {found.group(2)!r}, and QEMU virt's PL011 is at {QEMU_VIRT_PL011:#x}",
    )
    early = [text for text in texts[:position] if RECORD.match(text)]
    for text in early:
        require(
            BRING_UP.match(text) is not None,
            f"a record that is no part of the allocator's bring-up precedes the install marker: {text!r}",
        )
    later = [text for text in texts[position + 1 :] if RECORD.match(text)]
    require(bool(later), "no record follows the install marker")
    for index in range(position, len(complete)):
        require(
            complete[index].endswith(b"\r"),
            f"line {index + 1} ends in a line feed with no carriage return: {complete[index]!r}",
        )
    require(MARKER.search(tail) is None, "the capture ends inside an install marker")
    return Verdict(early=len(early), records=len(later), line_feeds=len(complete) - position)


_HONEST_CAPTURE = (
    b"seL4 kernel loader | INFO   Starting kernel\r\n"
    b"Bootstrapping kernel\r\n"
    b"SLIME_BACKING inventory parent=884 paddr=1610612736 bytes=65536\r\n"
    b"SLIME_ALLOC preserved untypeds=33\r\n"
    b"SLIME_ROOT metadata bootstrap objects=544784 alignment=36784 remaining=139264\r\n"
    b"SLIME_ROOT console uart=pl011 paddr=0x9000000\r\n"
    b"SLIME_ROOT allocator ready\r\n"
    b"[network-service] incarnation=1\r\n"
    b"SLIME_GRAPH HEALTHY\r\n"
)

_CAPTURE_MUTATIONS = (
    (
        "no install marker",
        'expected exactly one install marker',
        _HONEST_CAPTURE.replace(b"SLIME_ROOT console uart=pl011 paddr=0x9000000\r\n", b""),
    ),
    (
        "a root record before the marker",
        "no part of the allocator's bring-up precedes",
        _HONEST_CAPTURE.replace(b"Bootstrapping kernel\r\n", b"SLIME_ROOT allocator ready\r\n"),
    ),
    (
        "a component record before the marker",
        "no part of the allocator's bring-up precedes",
        _HONEST_CAPTURE.replace(b"Bootstrapping kernel\r\n", b"[network-service] incarnation=1\r\n"),
    ),
    (
        "a graph record before the marker",
        "no part of the allocator's bring-up precedes",
        _HONEST_CAPTURE.replace(b"Bootstrapping kernel\r\n", b"SLIME_GRAPH HEALTHY\r\n"),
    ),
    (
        "two install markers",
        'expected exactly one install marker',
        _HONEST_CAPTURE + b"SLIME_ROOT console uart=pl011 paddr=0x9000000\r\n",
    ),
    (
        "another UART's address",
        "QEMU virt's PL011 is at",
        _HONEST_CAPTURE.replace(b"paddr=0x9000000", b"paddr=0x9040000"),
    ),
    (
        "another UART kind",
        'not pl011',
        _HONEST_CAPTURE.replace(b"uart=pl011", b"uart=ns16550a"),
    ),
    (
        "a marker that shares its line",
        'shares its line',
        _HONEST_CAPTURE.replace(b"paddr=0x9000000\r\n", b"paddr=0x9000000 SLIME_ROOT allocator ready\r\n"),
    ),
    (
        "a line feed with no carriage return after the marker",
        'no carriage return',
        _HONEST_CAPTURE.replace(b"SLIME_GRAPH HEALTHY\r\n", b"SLIME_GRAPH HEALTHY\n"),
    ),
    (
        "no record after the marker",
        'no record follows the install marker',
        _HONEST_CAPTURE.split(b"SLIME_ROOT allocator ready")[0],
    ),
)


def capture_controls() -> int:
    """The honest capture passes; every mutation is refused. Returns the refusals."""
    judge(_HONEST_CAPTURE)
    # A kernel line before the marker may end in a bare line feed: the judge
    # holds the root to the rule only from its own first record.
    judge(_HONEST_CAPTURE.replace(b"Bootstrapping kernel\r\n", b"Bootstrapping kernel\n"))
    for description, reason, capture in _CAPTURE_MUTATIONS:
        try:
            judge(capture)
        except ValueError as error:
            require(reason in str(error), f"the capture judge refused {description} for another reason: {error}")
            continue
        raise ValueError(f"root console: the capture judge accepted {description}")
    return len(_CAPTURE_MUTATIONS)


# ---- the actual module, on the host ----

_EXAM = r"""
// Host adapters for the two kernel operations `diagnostic.rs` names, and a
// PL011 register page of plain memory.
extern crate self as sel4;
use std::sync::Mutex;
use std::time::Duration;

static KERNEL: Mutex<Vec<u8>> = Mutex::new(Vec::new());
pub fn debug_put_char(byte: u8) { KERNEL.lock().unwrap().push(byte); }
pub fn r#yield() { std::thread::yield_now(); }
fn kernel() -> Vec<u8> { std::mem::take(&mut *KERNEL.lock().unwrap()) }

@MODULE@

#[repr(C, align(4096))]
struct Page(std::cell::UnsafeCell<[u32; 1024]>);
// SAFETY: every access is a volatile 32-bit read or write of one register.
unsafe impl Sync for Page {}
static PAGE: Page = Page(std::cell::UnsafeCell::new([0; 1024]));
const DATA: usize = 0x000;
const FLAGS: usize = 0x018;
const TRANSMIT_FULL: u32 = 1 << 5;
const UNWRITTEN: u32 = 0xffff_ffff;
fn register(offset: usize) -> *mut u32 { (PAGE.0.get() as *mut u32).wrapping_add(offset / 4) }
fn get(offset: usize) -> u32 { unsafe { register(offset).read_volatile() } }
fn set(offset: usize, value: u32) { unsafe { register(offset).write_volatile(value) } }

fn main() {
    let mut cases = 0;

    // Before install the kernel receives the record unchanged, and no
    // register is written.
    set(DATA, UNWRITTEN);
    diagnostic::write(b"A\n").unwrap();
    assert_eq!(kernel(), b"A\n", "before install the kernel sink did not receive the record unchanged");
    assert_eq!(get(DATA), UNWRITTEN, "before install the data register was written");
    cases += 1;

    // After install the UART receives the record and the kernel receives nothing.
    diagnostic::install(PAGE.0.get() as usize);
    diagnostic::write(b"BC").unwrap();
    assert!(kernel().is_empty(), "after install the kernel sink received bytes");
    assert_eq!(get(DATA), u32::from(b'C'), "after install the data register does not hold the last byte");
    cases += 1;
    diagnostic::print(format_args!("{}\n", 7));
    assert!(kernel().is_empty(), "after install the kernel sink received bytes");
    assert_eq!(get(DATA), u32::from(b'\n'), "after install the data register does not hold the last byte");
    cases += 1;

    // A refused record reaches neither route.
    set(DATA, UNWRITTEN);
    assert!(diagnostic::write(&[b'Q'; 1025]).is_err(), "an oversize record was accepted");
    assert!(diagnostic::write(b"\xff").is_err(), "a record that is not UTF-8 was accepted");
    assert!(kernel().is_empty(), "a refused record reached the kernel sink");
    assert_eq!(get(DATA), UNWRITTEN, "a refused record reached the UART");
    cases += 1;

    // A full transmit FIFO holds the writer until the flag clears.
    set(FLAGS, TRANSMIT_FULL);
    let writer = std::thread::spawn(|| diagnostic::write(b"E").unwrap());
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(get(DATA), UNWRITTEN, "the data register was written while the transmit FIFO was full");
    assert!(!writer.is_finished(), "the writer returned while the transmit FIFO was full");
    set(FLAGS, 0);
    writer.join().unwrap();
    assert_eq!(get(DATA), u32::from(b'E'), "the byte was not written after the transmit FIFO drained");
    assert!(kernel().is_empty(), "after install the kernel sink received bytes");
    cases += 1;

    println!("root console exam: cases={cases} kernel_bytes_after_install=0");
}
"""

# A synthetic subject with the qualified behavior. The controls mutate it; it
# grades the exam's sensitivity and never stands in for the product module.
_SUBJECT = r"""
mod diagnostic {
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static UART: AtomicUsize = AtomicUsize::new(0);
    pub fn install(registers: usize) { UART.store(registers, Ordering::Release); }
    pub fn write(bytes: &[u8]) -> Result<(), std::fmt::Error> {
        if bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() { return Err(std::fmt::Error); }
        let uart = UART.load(Ordering::Acquire);
        for byte in bytes {
            if uart == 0 { crate::debug_put_char(*byte); } else { put(uart, *byte); }
        }
        Ok(())
    }
    fn put(uart: usize, byte: u8) {
        unsafe {
            while ((uart + 0x018) as *const u32).read_volatile() & (1 << 5) != 0 { std::hint::spin_loop(); }
            ((uart + 0x000) as *mut u32).write_volatile(u32::from(byte));
        }
    }
    pub fn print(args: std::fmt::Arguments<'_>) {
        let mut text = String::new();
        if text.write_fmt(args).is_ok() { let _ = write(text.as_bytes()); }
    }
}
"""

_SUBJECT_MUTATIONS = (
    (
        "a writer that keeps the kernel sink after install",
        "if uart == 0 { crate::debug_put_char(*byte); } else { put(uart, *byte); }",
        "crate::debug_put_char(*byte);",
        "after install the kernel sink received bytes",
    ),
    (
        "a writer that feeds both routes",
        "if uart == 0 { crate::debug_put_char(*byte); } else { put(uart, *byte); }",
        "crate::debug_put_char(*byte); if uart != 0 { put(uart, *byte); }",
        "after install the kernel sink received bytes",
    ),
    (
        "a writer that reaches the UART before install",
        "if uart == 0 { crate::debug_put_char(*byte); } else { put(uart, *byte); }",
        "crate::debug_put_char(*byte); put(crate::PAGE.0.get() as usize, *byte);",
        "before install the data register was written",
    ),
    (
        "a writer that emits a prefix of a refused record",
        "if bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() { return Err(std::fmt::Error); }",
        "if bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() "
        "{ let uart = UART.load(Ordering::Acquire); if uart != 0 { put(uart, b'!'); } return Err(std::fmt::Error); }",
        "a refused record reached the UART",
    ),
    (
        "a writer that sends a refused record's first byte to the kernel sink",
        "if bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() { return Err(std::fmt::Error); }",
        "if bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() "
        "{ if UART.load(Ordering::Acquire) != 0 { crate::debug_put_char(b'!'); } return Err(std::fmt::Error); }",
        "a refused record reached the kernel sink",
    ),
    (
        "a writer that accepts an oversize record",
        "if bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() { return Err(std::fmt::Error); }",
        "if std::str::from_utf8(bytes).is_err() { return Err(std::fmt::Error); }",
        "an oversize record was accepted",
    ),
    (
        "a writer that accepts a record that is not UTF-8",
        "if bytes.len() > 1024 || std::str::from_utf8(bytes).is_err() { return Err(std::fmt::Error); }",
        "if bytes.len() > 1024 { return Err(std::fmt::Error); }",
        "a record that is not UTF-8 was accepted",
    ),
    (
        "a writer that changes a record on the kernel route",
        "if uart == 0 { crate::debug_put_char(*byte); } else { put(uart, *byte); }",
        "if uart == 0 { if *byte == b'\\n' { crate::debug_put_char(b'\\r'); } crate::debug_put_char(*byte); } "
        "else { put(uart, *byte); }",
        "before install the kernel sink did not receive the record unchanged",
    ),
    (
        "a writer that drops the bytes after install",
        "if uart == 0 { crate::debug_put_char(*byte); } else { put(uart, *byte); }",
        "if uart == 0 { crate::debug_put_char(*byte); }",
        "after install the data register does not hold the last byte",
    ),
    (
        "a writer that ignores a full transmit FIFO",
        "while ((uart + 0x018) as *const u32).read_volatile() & (1 << 5) != 0 { std::hint::spin_loop(); }",
        "",
        "the data register was written while the transmit FIFO was full",
    ),
)


def _run(source: str, timeout: int) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="root-console-exam-") as directory:
        rust = Path(directory) / "exam.rs"
        binary = Path(directory) / "exam"
        rust.write_text(source, encoding="utf-8")
        compiled = subprocess.run(
            ["rustc", "--edition=2024", "-A", "warnings", str(rust), "-o", str(binary)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if compiled.returncode:
            return compiled
        return subprocess.run([str(binary)], capture_output=True, text=True, timeout=timeout, check=False)


def run_exam(root: Path, timeout: int = 60) -> int:
    """Run the exam on the actual module. Returns the cases it passed."""
    module = f'#[path = "{(root / DIAGNOSTIC).resolve()}"] mod diagnostic;'
    try:
        result = _run(_EXAM.replace("@MODULE@", module), timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"root console: the host exam did not finish: {error}") from error
    require(
        result.returncode == 0,
        f"the host exam refused {DIAGNOSTIC}:\n{result.stdout}{result.stderr}",
    )
    found = re.fullmatch(r"root console exam: cases=(\d+) kernel_bytes_after_install=0\n", result.stdout)
    require(found is not None, f"the host exam printed an unexpected report: {result.stdout!r}")
    return int(found.group(1))


def exam_controls(timeout: int = 60) -> int:
    """The synthetic subject passes; each mutation fails for its own reason."""
    try:
        positive = _run(_EXAM.replace("@MODULE@", _SUBJECT), timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"root console: the exam's positive control did not finish: {error}") from error
    require(positive.returncode == 0, f"the exam refused its positive control:\n{positive.stderr}")
    for description, old, new, reason in _SUBJECT_MUTATIONS:
        require(_SUBJECT.count(old) == 1, f"control source drifted: {description}")
        try:
            result = _run(_EXAM.replace("@MODULE@", _SUBJECT.replace(old, new)), timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"root console: the control did not finish: {description}: {error}") from error
        require(
            result.returncode != 0 and reason in result.stderr,
            f"the exam accepted {description}, or refused it for another reason:\n{result.stderr}",
        )
    return len(_SUBJECT_MUTATIONS)


# ---- the root's sources ----

_BRANCH = re.compile(
    r"let\s+uart\s*=\s*UART\s*\.\s*load\s*\(\s*Ordering\s*::\s*Acquire\s*\)\s*;\s*"
    r"for\s+byte\s+in\s+bytes\s*\{\s*"
    r"if\s+uart\s*==\s*0\s*\{\s*sel4\s*::\s*debug_put_char\s*\(\s*\*\s*byte\s*\)\s*;\s*\}\s*"
    r"else\s*\{\s*"
    r"if\s+\*\s*byte\s*==\s*b'\\n'\s*\{\s*put\s*\(\s*uart\s*,\s*b'\\r'\s*\)\s*;\s*\}\s*"
    r"put\s*\(\s*uart\s*,\s*\*\s*byte\s*\)\s*;\s*\}\s*\}"
)
_INSTALL = re.compile(
    r"pub\s+fn\s+install\s*\(\s*registers\s*:\s*usize\s*\)\s*\{\s*"
    r"UART\s*\.\s*store\s*\(\s*registers\s*,\s*Ordering\s*::\s*Release\s*\)\s*;\s*\}"
)
_SINK = re.compile(r"static\s+UART\s*:\s*AtomicUsize\s*=\s*AtomicUsize\s*::\s*new\s*\(\s*0\s*\)\s*;")
_UART_ACCESS = re.compile(r"\bUART\s*\.\s*(\w+)")
# Two ways a source can name the install: the path itself, or a brace list of
# a `use` that holds it. The audit accepts one of them, a direct call. It does
# not follow an alias of the module `diagnostic` or a glob import from it.
_INSTALL_NAME = re.compile(r"\bdiagnostic\s*::\s*(?:install\b|\{[^}]*\binstall\b[^}]*\})")
_INSTALL_CALL = re.compile(r"\bdiagnostic\s*::\s*install\s*\(")
_GUARDED_CALL = re.compile(
    r"#\s*\[\s*cfg\s*\(\s*" + CONFIGURATION + r"\s*\)\s*\]\s*"
    r"(?:#\s*\[\s*cfg_attr\s*\(\s*not\s*\(\s*slime_qemu_keyboard\s*\)\s*,\s*"
    r"allow\s*\(\s*unused_variables\s*\)\s*\)\s*\]\s*)?"
    r"let\s+console_registers\s*=\s*\{"
    r"(?P<body>.*?)\bslime_root\s*::\s*diagnostic\s*::\s*install\s*\(\s*console_addr\s*\)\s*;",
    re.DOTALL,
)
_MAPPED = re.compile(
    r"device\s*::\s*DeviceRegion\s*::\s*map\s*\(\s*allocator\s*,\s*"
    r"sel4\s*::\s*init_thread\s*::\s*slot\s*::\s*VSPACE\s*\.\s*cap\s*\(\s*\)\s*,\s*"
    r"console_addr\s*,\s*device\s*::\s*QEMU_PL011_PADDR\s*,?\s*\)"
)
_ADDRESS = re.compile(r"pub\s+const\s+QEMU_PL011_PADDR\s*:\s*usize\s*=\s*([0-9a-fA-Fx_]+)\s*;")
_RECORD_MACRO = re.compile(r"\bdiagnostic_print(?:ln)?\s*!")
_PROFILE_RULE = re.compile(
    r'if\s+target_profile\s*==\s*"' + re.escape(PROFILE) + r'"\s*\{\s*'
    r'println\s*!\s*\(\s*"cargo::rustc-cfg=' + CONFIGURATION + r'"\s*\)\s*;\s*\}'
)


def _source(root: Path, relative: str) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"root console: cannot read {relative}: {error}") from error


def audit(root: Path) -> None:
    """Raise ValueError unless the root's sources install the PL011 once, in
    `main`, before its first record, on the one target profile."""
    diagnostic = _code(_source(root, DIAGNOSTIC))
    require(_SINK.search(diagnostic) is not None, f"{DIAGNOSTIC} declares no UART sink that starts at zero")
    require(_INSTALL.search(diagnostic) is not None, f"{DIAGNOSTIC} has no install that only stores the address")
    require(
        _BRANCH.search(diagnostic) is not None,
        f"{DIAGNOSTIC} does not send each byte to the kernel only while no UART is installed",
    )
    accesses = sorted(_UART_ACCESS.findall(diagnostic))
    require(accesses == ["load", "store"], f"{DIAGNOSTIC} reads or writes the UART sink elsewhere: {accesses}")
    put = re.search(r"\bfn\s+put\s*\(\s*uart\s*:\s*usize\s*,\s*byte\s*:\s*u8\s*\)\s*\{", diagnostic)
    require(put is not None, f"{DIAGNOSTIC} has no put(uart, byte)")
    body = diagnostic[put.end() :]
    require(
        body.find("read_volatile") != -1 and body.find("read_volatile") < body.find("write_volatile"),
        f"{DIAGNOSTIC} put does not read the flag register before it writes the data register",
    )

    calls = []
    for path in sorted((root / "slime-root").rglob("*.rs")):
        code = _code(path.read_text(encoding="utf-8"))
        relative = str(path.relative_to(root))
        for name in _INSTALL_NAME.finditer(code):
            # An import, a re-export or a function value would let a later
            # line call install under a name this audit does not follow.
            require(
                _INSTALL_CALL.match(code, name.start()) is not None,
                f"{relative} names diagnostic::install without calling it: {name.group(0)!r}",
            )
            calls.append(relative)
    require(calls == [BINARY], f"expected one diagnostic::install call, in {BINARY}; found {calls}")

    binary = _code(_source(root, BINARY))
    entry = re.search(r"\bfn\s+main\s*\(\s*bootinfo\b", binary)
    require(entry is not None, f"{BINARY} has no main(bootinfo)")
    main = binary[entry.start() :]
    guarded = _GUARDED_CALL.search(main)
    require(
        guarded is not None,
        f"{BINARY} does not install the console inside a #[cfg({CONFIGURATION})] block of main",
    )
    require(
        _MAPPED.search(guarded.group("body")) is not None,
        f"{BINARY} does not map device::QEMU_PL011_PADDR at the address it installs",
    )
    first = _RECORD_MACRO.search(main)
    require(
        first is None or guarded.end() < first.start(),
        f"{BINARY} emits a record in main before it installs the console",
    )

    address = _ADDRESS.search(_code(_source(root, DEVICE)))
    require(address is not None, f"{DEVICE} declares no QEMU_PL011_PADDR")
    require(
        int(address.group(1).replace("_", ""), 16) == QEMU_VIRT_PL011,
        f"{DEVICE} names {address.group(1)}, and QEMU virt's PL011 is at {QEMU_VIRT_PL011:#x}",
    )

    build = _code(_source(root, BUILD))
    require(
        len(re.findall(r"rustc-cfg=" + CONFIGURATION, _source(root, BUILD))) == 1
        and _PROFILE_RULE.search(build) is not None,
        f"{BUILD} does not set {CONFIGURATION} for {PROFILE} and no other profile",
    )


_TREE = {
    DIAGNOSTIC: r"""
use core::sync::atomic::{AtomicUsize, Ordering};
static UART: AtomicUsize = AtomicUsize::new(0);
pub fn install(registers: usize) {
    UART.store(registers, Ordering::Release);
}
pub fn write(bytes: &[u8]) -> Result<(), core::fmt::Error> {
    let uart = UART.load(Ordering::Acquire);
    for byte in bytes {
        if uart == 0 {
            sel4::debug_put_char(*byte);
        } else {
            if *byte == b'\n' {
                put(uart, b'\r');
            }
            put(uart, *byte);
        }
    }
    Ok(())
}
fn put(uart: usize, byte: u8) {
    unsafe {
        while ((uart + 0x018) as *const u32).read_volatile() & (1 << 5) != 0 {}
        ((uart + 0x000) as *mut u32).write_volatile(u32::from(byte));
    }
}
""",
    BINARY: r"""
fn earlier() {
    slime_root::diagnostic_println!("SLIME_TIMER OK");
}
fn main(bootinfo: &sel4::BootInfoPtr) -> ! {
    #[cfg(slime_root_console_pl011)]
    #[cfg_attr(not(slime_qemu_keyboard), allow(unused_variables))]
    let console_registers = {
        let console_addr = ptr::addr_of!(ROOT_CONSOLE_PAGE) as usize;
        let registers = match device::DeviceRegion::map(
            allocator,
            sel4::init_thread::slot::VSPACE.cap(),
            console_addr,
            device::QEMU_PL011_PADDR,
        ) {
            Ok(registers) => registers,
            Err(error) => fatal!("root console UART unavailable: {error:?}"),
        };
        slime_root::diagnostic::install(console_addr);
        slime_root::diagnostic_println!("SLIME_ROOT console uart=pl011 paddr={:#x}", device::QEMU_PL011_PADDR);
        registers
    };
    slime_root::diagnostic_println!("SLIME_ROOT allocator ready");
}
""",
    DEVICE: "pub const QEMU_PL011_PADDR: usize = 0x0900_0000;\n",
    BUILD: r"""
fn main() {
    if target_profile == "aarch64-sel4-qemu-virt" {
        println!("cargo::rustc-cfg=slime_root_console_pl011");
    }
}
""",
}

_TREE_MUTATIONS = (
    (
        "a kernel sink that does not depend on the installed UART",
        'only while no UART is installed',
        DIAGNOSTIC,
        "if uart == 0 {\n            sel4::debug_put_char(*byte);\n        } else {",
        "sel4::debug_put_char(*byte);\n        if uart != 0 {",
    ),
    (
        "an inverted route",
        'only while no UART is installed',
        DIAGNOSTIC,
        "if uart == 0 {",
        "if uart != 0 {",
    ),
    (
        "no carriage return before a line feed",
        'only while no UART is installed',
        DIAGNOSTIC,
        "if *byte == b'\\n' {\n                put(uart, b'\\r');\n            }\n",
        "",
    ),
    (
        "an install that can be undone",
        'reads or writes the UART sink elsewhere',
        DIAGNOSTIC,
        "fn put(uart: usize, byte: u8) {",
        "pub fn remove() { UART.store(0, Ordering::Release); }\nfn put(uart: usize, byte: u8) {",
    ),
    (
        "a UART sink that does not start at zero",
        "declares no UART sink that starts at zero",
        DIAGNOSTIC,
        "static UART: AtomicUsize = AtomicUsize::new(0);",
        "static UART: AtomicUsize = AtomicUsize::new(0x0900_0000);",
    ),
    (
        "an install that stores another address",
        "has no install that only stores the address",
        DIAGNOSTIC,
        "UART.store(registers, Ordering::Release);",
        "UART.store(registers & !0xfff, Ordering::Release);",
    ),
    (
        "a data register written before the flag register is read",
        'does not read the flag register before',
        DIAGNOSTIC,
        "while ((uart + 0x018) as *const u32).read_volatile() & (1 << 5) != 0 {}\n"
        "        ((uart + 0x000) as *mut u32).write_volatile(u32::from(byte));",
        "((uart + 0x000) as *mut u32).write_volatile(u32::from(byte));\n"
        "        while ((uart + 0x018) as *const u32).read_volatile() & (1 << 5) != 0 {}",
    ),
    (
        "a second install call",
        'expected one diagnostic::install call',
        BINARY,
        "fn earlier() {",
        "fn earlier() {\n    slime_root::diagnostic::install(0);",
    ),
    (
        "an imported install called by its bare name",
        "names diagnostic::install without calling it",
        BINARY,
        "fn earlier() {",
        "use slime_root::diagnostic::install;\nfn earlier() {\n    install(0);",
    ),
    (
        "an install imported through a brace list",
        "names diagnostic::install without calling it",
        BINARY,
        "fn earlier() {",
        "use slime_root::diagnostic::{install, write};\nfn earlier() {\n    install(0);",
    ),
    (
        "an install taken as a function value",
        "names diagnostic::install without calling it",
        BINARY,
        "fn earlier() {",
        "fn earlier() {\n    let route = slime_root::diagnostic::install;\n    route(0);",
    ),
    (
        "an install imported inside another target profile's block",
        "names diagnostic::install without calling it",
        BINARY,
        '    slime_root::diagnostic_println!("SLIME_ROOT allocator ready");',
        '    slime_root::diagnostic_println!("SLIME_ROOT allocator ready");\n'
        "    #[cfg(slime_product_uart)]\n    {\n        use slime_root::diagnostic::install;\n"
        "        install(uart_addr);\n    }",
    ),
    (
        "an install outside the target profile's block",
        'does not install the console inside',
        BINARY,
        "    #[cfg(slime_root_console_pl011)]\n    #[cfg_attr(",
        "    #[cfg_attr(",
    ),
    (
        "a record of main before the install",
        'emits a record in main before',
        BINARY,
        "    #[cfg(slime_root_console_pl011)]",
        '    slime_root::diagnostic_println!("SLIME_ROOT early");\n    #[cfg(slime_root_console_pl011)]',
    ),
    (
        "an installed address that is not the mapped one",
        'does not map device::QEMU_PL011_PADDR',
        BINARY,
        "console_addr,\n            device::QEMU_PL011_PADDR,",
        "other_addr,\n            device::QEMU_PL011_PADDR,",
    ),
    (
        "another physical address",
        "QEMU virt's PL011 is at",
        DEVICE,
        "0x0900_0000",
        "0x0904_0000",
    ),
    (
        "a build script that sets the configuration for every profile",
        'does not set',
        BUILD,
        'if target_profile == "aarch64-sel4-qemu-virt" {',
        "{",
    ),
)


def audit_controls() -> int:
    """The synthetic tree passes; every mutation is refused. Returns the refusals."""
    with tempfile.TemporaryDirectory(prefix="root-console-audit-") as directory:
        root = Path(directory)
        for relative, source in _TREE.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        audit(root)
        for description, reason, relative, old, new in _TREE_MUTATIONS:
            require(_TREE[relative].count(old) == 1, f"control source drifted: {description}")
            path = root / relative
            path.write_text(_TREE[relative].replace(old, new), encoding="utf-8")
            try:
                audit(root)
            except ValueError as error:
                refusal = str(error)
            else:
                raise ValueError(f"root console: the source audit accepted {description}")
            finally:
                path.write_text(_TREE[relative], encoding="utf-8")
            require(reason in refusal, f"the source audit refused {description} for another reason: {refusal}")
    return len(_TREE_MUTATIONS)


def controls() -> int:
    """Every negative control of the three judges. Returns the refusals."""
    return capture_controls() + exam_controls() + audit_controls()
