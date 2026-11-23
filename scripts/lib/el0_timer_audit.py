"""Find AArch64 instructions that read or write a generic-timer register from EL0.

An EL0 program names a generic-timer register through `MRS` or `MSR` with
op0 = 3, op1 = 3 and CRn = 14. Those are `CNTFRQ_EL0`, the two counters, and
the three registers of the physical timer and of the virtual timer. The kernel
lets EL0 use them per configuration option, and without the option the
instruction traps. The verified kernel configuration sets none of the options
(`docs/decisions/verified-kernel-profile.md`), so an image for it holds no such
instruction in any EL0 program.

`accesses` reads code as 4-byte words. `elf_code` gives the executable load
segments of an ELF64 file, read by the standard's layout. `image_code` gives
the executable segments of a component image, and `generation_images` the
image of every executable of a generation; both read through the generated
bindings of their contracts. Each refuses what it cannot read: an audit of
bytes it did not understand proves nothing.

The audit reads code only. A data word with the same bits is no instruction,
and a word that the processor never reaches still counts: the property is
that the program holds none, which no input can change.

A known limit follows from reading whole segments. A data word inside an
executable segment with the bits of an access is reported as one. The audit
then refuses an image that holds no access; it never accepts one that does.

`controls` runs the negative controls of all four. Standard library and the
generated bindings only.
"""

from __future__ import annotations

import hashlib
import struct

import boot_contracts

# MRS and MSR of a system register share one layout. Bit 21 is L: 1 reads.
# The mask keeps every bit but L and the five bits of Rt, and leaves CRm and
# op2 to the name table.
SYSTEM_REGISTER_MASK = 0xFFDF_F000
EL0_GENERIC_TIMER = 0xD51B_E000
READ = 1 << 21
# (CRm, op2) of every generic-timer register that EL0 can name.
REGISTERS = {
    (0, 0): "CNTFRQ_EL0",
    (0, 1): "CNTPCT_EL0",
    (0, 2): "CNTVCT_EL0",
    (2, 0): "CNTP_TVAL_EL0",
    (2, 1): "CNTP_CTL_EL0",
    (2, 2): "CNTP_CVAL_EL0",
    (3, 0): "CNTV_TVAL_EL0",
    (3, 1): "CNTV_CTL_EL0",
    (3, 2): "CNTV_CVAL_EL0",
}
ELF_MACHINE_AARCH64 = 183
ELF_HEADER = struct.Struct("<4sBBBBB7xHHIQQQIHHHHHH")
ELF_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
PT_LOAD = 1
PF_X = 1


class AuditError(ValueError):
    """The bytes are not a program this audit can read."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def accesses(code: bytes) -> list[tuple[int, str]]:
    """`(offset, text)` of every access in `code`, a run of 4-byte instructions.

    A register of the group that the table does not name is reported by its
    encoding: an unknown register of the generic timer is still one."""
    require(len(code) % 4 == 0, "code length is not a multiple of four bytes")
    found = []
    for offset in range(0, len(code), 4):
        (word,) = struct.unpack_from("<I", code, offset)
        if word & SYSTEM_REGISTER_MASK != EL0_GENERIC_TIMER:
            continue
        crm, op2 = (word >> 8) & 15, (word >> 5) & 7
        register = REGISTERS.get((crm, op2), f"S3_3_C14_C{crm}_{op2}")
        found.append((offset, f"{'mrs' if word & READ else 'msr'} {register}"))
    return found


def elf_code(elf: bytes) -> list[bytes]:
    """The file bytes of every executable load segment of an AArch64 ELF64."""
    require(len(elf) >= ELF_HEADER.size, "ELF is shorter than its header")
    magic, elf_class, data, version, _, _, _, machine, _, _, phoff, _, _, _, phentsize, phnum, _, _, _ = ELF_HEADER.unpack_from(elf)
    require(magic == b"\x7fELF" and elf_class == 2 and data == 1 and version == 1, "not a little-endian ELF64")
    require(machine == ELF_MACHINE_AARCH64, f"ELF machine {machine} is not AArch64")
    require(phentsize == ELF_PROGRAM_HEADER.size and phnum > 0, "ELF has no program header table of the standard size")
    require(phoff + phnum * phentsize <= len(elf), "ELF program header table leaves the file")
    code = []
    for index in range(phnum):
        kind, flags, offset, vaddr, _, filesz, _, _ = ELF_PROGRAM_HEADER.unpack_from(elf, phoff + index * phentsize)
        if kind != PT_LOAD or not flags & PF_X:
            continue
        require(offset + filesz <= len(elf), "ELF load segment leaves the file")
        require(vaddr % 4 == 0 and filesz % 4 == 0, "executable ELF segment is not a run of 4-byte instructions")
        code.append(elf[offset : offset + filesz])
    require(bool(code), "ELF has no executable load segment")
    return code


def image_code(image: bytes) -> list[bytes]:
    """The file bytes of every executable segment of an AArch64 component image."""
    header = boot_contracts.COMPONENT_IMAGE_HEADER
    require(len(image) >= header.size, "component image is shorter than its header")
    magic, version, header_size, _, _, _, _, _, segments, reserved, _, _, _ = header.unpack_from(image)
    require(version == boot_contracts.COMPONENT_IMAGE_VERSION and header_size == header.size and reserved == 0, "component image header is not version 2")
    if magic == boot_contracts.COMPONENT_IMAGE_ELF_MAGIC:
        return elf_code(image[header.size :])
    require(magic == boot_contracts.COMPONENT_IMAGE_MAGIC, f"component image magic {magic!r} is unknown")
    record = boot_contracts.COMPONENT_IMAGE_SEGMENT
    require(1 <= segments <= boot_contracts.COMPONENT_IMAGE_MAX_SEGMENTS, "component image segment count is out of range")
    payload = header.size + segments * record.size
    require(payload <= len(image), "component image segment table leaves the image")
    code = []
    for index in range(segments):
        vaddr_offset, _, file_offset, file_len, flags, _ = record.unpack_from(image, header.size + index * record.size)
        if not flags & boot_contracts.COMPONENT_SEGMENT_FLAG_EXEC:
            continue
        require(payload + file_offset + file_len <= len(image), "component image segment leaves the image")
        require(vaddr_offset % 4 == 0 and file_len % 4 == 0, "executable image segment is not a run of 4-byte instructions")
        code.append(image[payload + file_offset : payload + file_offset + file_len])
    require(bool(code), "component image has no executable segment")
    return code


def generation_images(generation: bytes) -> list[tuple[str, bytes]]:
    """`(name, component image)` of every executable row of a generation, in row order.

    The executable table is the list a root launches from, so an image that no
    row names is not a program of this generation."""
    header = boot_contracts.GENERATION_HEADER
    require(len(generation) >= header.size, "generation is shorter than its header")
    require(generation[:8] == boot_contracts.GENERATION_MAGIC, "generation magic is unknown")
    require(_word(generation, boot_contracts.GENERATION_HEADER_FORMAT_VERSION_OFFSET, 4) == boot_contracts.GENERATION_VERSION, "generation version is unknown")
    objects = _word(generation, boot_contracts.GENERATION_HEADER_OBJECT_COUNT_OFFSET, 4)
    executables = _word(generation, boot_contracts.GENERATION_HEADER_EXECUTABLE_COUNT_OFFSET, 4)
    object_offset = _word(generation, boot_contracts.GENERATION_HEADER_OBJECT_OFFSET_OFFSET, 8)
    executable_offset = _word(generation, boot_contracts.GENERATION_HEADER_EXECUTABLE_OFFSET_OFFSET, 8)
    strings_offset = _word(generation, boot_contracts.GENERATION_HEADER_STRING_OFFSET_OFFSET, 8)
    strings_len = _word(generation, boot_contracts.GENERATION_HEADER_STRING_LEN_OFFSET, 8)
    object_row, executable_row = boot_contracts.GENERATION_OBJECT, boot_contracts.GENERATION_EXECUTABLE
    require(executables > 0, "generation has no executable")
    require(object_offset + objects * object_row.size <= len(generation), "generation object table leaves the generation")
    require(executable_offset + executables * executable_row.size <= len(generation), "generation executable table leaves the generation")
    require(strings_offset + strings_len <= len(generation), "generation string table leaves the generation")
    images = []
    for index in range(executables):
        name_offset, object_index, _, _ = executable_row.unpack_from(generation, executable_offset + index * executable_row.size)
        require(object_index < objects, "executable row names an object outside the table")
        require(name_offset + 2 <= strings_len, "executable name leaves the string table")
        length = _word(generation, strings_offset + name_offset, 2)
        require(name_offset + 2 + length <= strings_len, "executable name leaves the string table")
        name = generation[strings_offset + name_offset + 2 : strings_offset + name_offset + 2 + length].decode("utf-8", "strict")
        _, _, payload_offset, payload_len, digest = object_row.unpack_from(generation, object_offset + object_index * object_row.size)
        require(payload_offset + payload_len <= len(generation), "executable image leaves the generation")
        image = generation[payload_offset : payload_offset + payload_len]
        require(hashlib.sha256(image).digest() == digest, f"image of {name} does not match its recorded digest")
        images.append((name, image))
    return images


def _word(data: bytes, offset: int, size: int) -> int:
    return int.from_bytes(data[offset : offset + size], "little")


def program_accesses(code: list[bytes]) -> list[str]:
    """The text of every access in a program's executable segments."""
    return [text for segment in code for _, text in accesses(segment)]


def _instruction(read: bool, crm: int, op2: int, rt: int) -> bytes:
    return struct.pack("<I", EL0_GENERIC_TIMER | (READ if read else 0) | crm << 8 | op2 << 5 | rt)


def _elf(segments: list[tuple[int, bytes]], machine: int = ELF_MACHINE_AARCH64) -> bytes:
    """A minimal ELF64 with one load segment per `(flags, bytes)`."""
    phoff = ELF_HEADER.size
    offset = phoff + len(segments) * ELF_PROGRAM_HEADER.size
    headers, body = b"", b""
    for flags, data in segments:
        headers += ELF_PROGRAM_HEADER.pack(PT_LOAD, flags, offset + len(body), 0x20_0000 + len(body), 0, len(data), len(data), 0x1000)
        body += data
    return ELF_HEADER.pack(b"\x7fELF", 2, 1, 1, 0, 0, 2, machine, 1, 0x20_0000, phoff, 0, 0, ELF_HEADER.size, ELF_PROGRAM_HEADER.size, len(segments), 0, 0, 0) + headers + body


def _image(segments: list[tuple[int, bytes]], magic: bytes = boot_contracts.COMPONENT_IMAGE_MAGIC) -> bytes:
    """A component image with one segment per `(flags, bytes)`."""
    records, payload = b"", b""
    for flags, data in segments:
        records += boot_contracts.COMPONENT_IMAGE_SEGMENT.pack(len(payload), len(data), len(payload), len(data), flags, 0)
        payload += data
    header = boot_contracts.COMPONENT_IMAGE_HEADER.pack(
        magic, boot_contracts.COMPONENT_IMAGE_VERSION, boot_contracts.COMPONENT_IMAGE_HEADER.size,
        boot_contracts.COMPONENT_IMAGE_KERNEL_ABI, 0, 0, 0, 0, len(segments), 0, 0x4000, 0, 0,
    )
    return header + records + payload


def _generation(images: list[tuple[str, bytes]], digest_of=lambda image: hashlib.sha256(image).digest()) -> bytes:
    """A generation that holds nothing but an executable row and an object per image."""
    header = boot_contracts.GENERATION_HEADER
    object_row, executable_row = boot_contracts.GENERATION_OBJECT, boot_contracts.GENERATION_EXECUTABLE
    strings = b"".join(struct.pack("<H", len(name)) + name.encode() for name, _ in images)
    object_offset = header.size
    executable_offset = object_offset + len(images) * object_row.size
    strings_offset = executable_offset + len(images) * executable_row.size
    payload_offset = strings_offset + len(strings)
    objects, executables, payloads, name_offset = b"", b"", b"", 0
    for index, (name, image) in enumerate(images):
        objects += object_row.pack(name_offset, 2, payload_offset + len(payloads), len(image), digest_of(image))
        executables += executable_row.pack(name_offset, index, 1, 0)
        payloads += image
        name_offset += 2 + len(name)
    head = bytearray(header.size)
    head[:8] = boot_contracts.GENERATION_MAGIC
    for offset, size, value in (
        (boot_contracts.GENERATION_HEADER_FORMAT_VERSION_OFFSET, 4, boot_contracts.GENERATION_VERSION),
        (boot_contracts.GENERATION_HEADER_OBJECT_COUNT_OFFSET, 4, len(images)),
        (boot_contracts.GENERATION_HEADER_EXECUTABLE_COUNT_OFFSET, 4, len(images)),
        (boot_contracts.GENERATION_HEADER_OBJECT_OFFSET_OFFSET, 8, object_offset),
        (boot_contracts.GENERATION_HEADER_EXECUTABLE_OFFSET_OFFSET, 8, executable_offset),
        (boot_contracts.GENERATION_HEADER_STRING_OFFSET_OFFSET, 8, strings_offset),
        (boot_contracts.GENERATION_HEADER_STRING_LEN_OFFSET, 8, len(strings)),
    ):
        head[offset : offset + size] = value.to_bytes(size, "little")
    return bytes(head) + objects + executables + strings + payloads


def controls() -> int:
    """Run the negative controls; return how many ran. Raises `AuditError` on the first that fails."""
    ran = 0

    def expect(condition: bool, name: str) -> None:
        nonlocal ran
        ran += 1
        require(condition, f"control '{name}' failed")

    def refused(function, argument: bytes) -> bool:
        try:
            function(argument)
        except AuditError:
            return True
        return False

    nop = struct.pack("<I", 0xD503_201F)
    # Every register, read and written, through the first and the last register operand.
    for (crm, op2), register in REGISTERS.items():
        for read in (True, False):
            for rt in (0, 30):
                text = f"{'mrs' if read else 'msr'} {register}"
                expect(accesses(nop + _instruction(read, crm, op2, rt)) == [(4, text)], f"{text} through x{rt}")
    expect(accesses(_instruction(True, 5, 3, 0)) == [(0, "mrs S3_3_C14_C5_3")], "a register of the group that the table does not name")
    # Neighbours in the encoding space that are no EL0 generic-timer register.
    for word, name in (
        (0xD503_201F, "nop"),
        (0xD538_E100, "mrs x0, cntkctl_el1: op1 is 0"),
        (0xD53C_E100, "mrs x0, cnthctl_el2: op1 is 4"),
        (0xD53B_D040, "mrs x0, tpidr_el0: CRn is 13"),
        (0xD53B_9D00, "mrs x0, pmccntr_el0: CRn is 9"),
        (0xD51B_4200, "msr nzcv, x0: CRn is 4"),
        (0xD50B_E020, "sys with the same op1 and CRn: op0 is 1"),
    ):
        expect(accesses(struct.pack("<I", word)) == [], name)
    access = _instruction(True, 0, 1, 0)
    expect(refused(accesses, access + b"\x00"), "code that is no run of 4-byte words")
    # An ELF: code counts, data does not, and what cannot be read is refused.
    expect(program_accesses(elf_code(_elf([(PF_X | 4, nop + access)]))) == ["mrs CNTPCT_EL0"], "an access in an executable ELF segment")
    expect(program_accesses(elf_code(_elf([(PF_X | 4, nop), (6, access)]))) == [], "the same word in a data segment of an ELF")
    expect(program_accesses(elf_code(_elf([(PF_X | 4, nop), (PF_X | 4, access)]))) == ["mrs CNTPCT_EL0"], "an access in the second executable ELF segment")
    expect(refused(elf_code, _elf([(6, access)])), "an ELF with no executable segment")
    expect(refused(elf_code, _elf([(PF_X | 4, access)], machine=62)), "an ELF for another machine")
    expect(refused(elf_code, _elf([(PF_X | 4, access)])[:-2]), "an ELF whose segment leaves the file")
    expect(refused(elf_code, b"\x7fELF"), "a truncated ELF")
    # A component image, in both payload forms.
    executable = boot_contracts.COMPONENT_SEGMENT_FLAG_EXEC
    writable = boot_contracts.COMPONENT_SEGMENT_FLAG_WRITE
    expect(program_accesses(image_code(_image([(executable, nop + access)]))) == ["mrs CNTPCT_EL0"], "an access in an executable image segment")
    expect(program_accesses(image_code(_image([(executable, nop), (writable, access)]))) == [], "the same word in a data segment of an image")
    expect(refused(image_code, _image([(writable, access)])), "an image with no executable segment")
    expect(refused(image_code, _image([(executable, access)])[:-2]), "an image whose segment leaves the image")
    expect(refused(image_code, _image([(executable, access)], magic=b"SLIMECMX")), "an image with an unknown magic")
    wrapped = boot_contracts.COMPONENT_IMAGE_HEADER.pack(
        boot_contracts.COMPONENT_IMAGE_ELF_MAGIC, boot_contracts.COMPONENT_IMAGE_VERSION,
        boot_contracts.COMPONENT_IMAGE_HEADER.size, boot_contracts.COMPONENT_IMAGE_KERNEL_ABI, 0, 0, 0, 0, 0, 0, 0x4000, 0, 0,
    ) + _elf([(PF_X | 4, access)])
    expect(program_accesses(image_code(wrapped)) == ["mrs CNTPCT_EL0"], "an access in an image that wraps an ELF")
    # A generation: every executable row is read, and a row the audit cannot follow is refused.
    clean, dirty = _image([(executable, nop)]), _image([(executable, nop + access)])
    found = [(name, program_accesses(image_code(image))) for name, image in generation_images(_generation([("clean", clean), ("dirty", dirty)]))]
    expect(found == [("clean", []), ("dirty", ["mrs CNTPCT_EL0"])], "an access in the second executable of a generation")
    expect(refused(generation_images, _generation([("dirty", dirty)], digest_of=lambda image: bytes(32))), "an image that does not match its digest")
    expect(refused(generation_images, _generation([("dirty", dirty)])[:-2]), "a generation whose image leaves it")
    expect(refused(generation_images, _generation([])), "a generation with no executable")
    expect(refused(generation_images, b"SLIMEG4\0" + _generation([("dirty", dirty)])[8:]), "a generation with another magic")
    return ran
