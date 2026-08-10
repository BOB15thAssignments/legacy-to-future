"""Read and compare PE exports, imports, and consumer requirements."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

import lief

logger = logging.getLogger(__name__)

__all__ = [
    "ExportEntry", "Surface", "export_key",
    "read_exports", "read_imports", "required_surface",
    "scan_dynamic_candidates", "compare_contract_surface", "compare_surface",
]

# IMAGE_SCN_* — an export whose RVA lands outside code is a data export.
_SCN_CNT_CODE = 0x00000020
_SCN_MEM_EXECUTE = 0x20000000

_MACHINE_ARCH = {
    "AMD64": "x64", "I386": "x86", "ARM64": "arm64",
    "ARMNT": "arm", "ARM": "arm", "IA64": "ia64",
}

# Export names are C identifiers or MSVC-mangled ones; `?@$` are mangling
# characters and `.` shows up in forwarder spellings.
_TOKEN_RE = re.compile(r"[A-Za-z_?@$][A-Za-z0-9_?@$.]*")
_STRING_RE_CACHE: dict[tuple[str, int], re.Pattern[bytes]] = {}


@dataclass
class ExportEntry:
    name: str | None
    ordinal: int
    rva: int
    forwarder: tuple[str, str] | None
    # None is deliberately distinct from code.  Treating a parser failure as
    # `False` used to let an unclassified data export earn function coverage.
    is_data: bool | None = None

    @property
    def is_noname(self) -> bool:
        return self.name is None

    @property
    def key(self) -> str:
        return export_key(self)


@dataclass
class Surface:
    module: str
    arch: str                          # x64 | x86 (| arm64 | ... when honest)
    exports: dict[str, ExportEntry]    # keyed by name, or "#<ord>" when NONAME
    by_ordinal: dict[int, ExportEntry]
    # Additive beyond the spec: the exact machine word is what a loader
    # actually rejects on, and `arch` alone cannot distinguish x64 from arm64.
    machine: str = ""
    path: str = ""

    @property
    def names(self) -> set[str]:
        """Real exported names, excluding synthetic `#<ord>` keys."""
        return {e.name for e in self.exports.values() if e.name}

    def get(self, name_or_key: str) -> ExportEntry | None:
        return self.exports.get(name_or_key)


def export_key(entry: ExportEntry) -> str:
    """Dictionary key for an export: its name, or `#<ordinal>` when NONAME."""
    return entry.name if entry.name else f"#{entry.ordinal}"


# --------------------------------------------------------------------------
# LIEF plumbing
# --------------------------------------------------------------------------

def _attr(obj: Any, *names: str, default: Any = None) -> Any:
    """Value of the first readable attribute in `names`, else `default`."""
    if obj is None:
        return default
    for n in names:
        try:
            if not hasattr(obj, n):
                continue
            v = getattr(obj, n)
        except Exception:                      # noqa: BLE001 - LIEF raises freely
            logger.debug("attribute %r raised on %r", n, type(obj).__name__)
            continue
        if v is not None:
            return v
    return default


_MISSING = object()


def _required_attr(obj: Any, *names: str, context: str) -> Any:
    """Read a required LIEF attribute without converting errors to absence."""
    if obj is None:
        raise ValueError(f"{context}: owner object is unavailable")
    errors: list[str] = []
    for name in names:
        try:
            value = getattr(obj, name, _MISSING)
        except Exception as exc:              # noqa: BLE001 - evidence defect
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if value is not _MISSING and value is not None:
            return value
    if errors:
        raise ValueError(f"{context}: attribute read failed ({'; '.join(errors)})")
    raise ValueError(
        f"{context}: none of required attributes {', '.join(names)} exists")


def _enum_name(value: Any) -> str:
    """Readable name of a LIEF enum member, whatever the binding does."""
    if value is None:
        return ""
    n = getattr(value, "name", None)
    if isinstance(n, str) and n:
        return n
    return str(value).rsplit(".", 1)[-1]


def _parse(path: str | Path) -> Any:
    """Parse a PE image.

    The file is opened by Python and handed to LIEF as a stream. LIEF's
    filename overload goes through a narrow-char open and fails outright on
    any path holding non-ANSI characters, which on a localized Windows
    install means most user profiles.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"not a file: {p}")
    binary = None
    try:
        with open(p, "rb") as fh:
            binary = lief.PE.parse(fh)
    except TypeError:                          # binding without the stream overload
        logger.debug("lief.PE.parse has no stream overload, using the path")
        binary = lief.PE.parse(str(p))
    if binary is None:
        raise ValueError(f"not a PE image: {p}")
    return binary


def _detect_arch(binary: Any) -> str:
    magic = _enum_name(_attr(_attr(binary, "optional_header"), "magic"))
    if "PE32_PLUS" in magic or "PE64" in magic:     # order matters: PE32 is a prefix
        return "x64"
    if "PE32" in magic:
        return "x86"
    machine = _detect_machine(binary)
    arch = _MACHINE_ARCH.get(machine)
    if arch:
        logger.debug("optional_header.magic unreadable, fell back to machine %s",
                     machine)
        return arch
    logger.warning("cannot determine arch (magic=%r machine=%r)", magic, machine)
    return "unknown"


def _detect_machine(binary: Any) -> str:
    return _enum_name(_attr(_attr(binary, "header"), "machine"))


def _looks_like_data(binary: Any, rva: int) -> bool:
    """Classify an export RVA, raising when the PE cannot prove its kind."""
    if rva <= 0:
        raise ValueError(f"export has no classifiable RVA ({rva})")
    try:
        section = binary.section_from_rva(rva)
    except Exception as exc:                   # noqa: BLE001
        raise ValueError(
            f"section lookup failed for export RVA 0x{rva:x}: "
            f"{type(exc).__name__}: {exc}") from exc
    if section is None:
        raise ValueError(f"no PE section contains export RVA 0x{rva:x}")
    chars = _required_attr(
        section, "characteristics",
        context=f"section characteristics for export RVA 0x{rva:x}")
    try:
        chars = int(chars)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"invalid section characteristics for export RVA 0x{rva:x}: "
            f"{chars!r}") from exc
    return not (chars & (_SCN_CNT_CODE | _SCN_MEM_EXECUTE))


def _forwarder_of(entry: Any) -> tuple[str, str] | None:
    is_fwd = bool(_required_attr(
        entry, "is_forwarded", "is_forwarder",
        context="export forwarder flag"))
    if not is_fwd:
        return None
    info = _required_attr(
        entry, "forward_information", "forwarder_info",
        context="forwarded export information")
    library = str(_required_attr(
        info, "library", context="forwarded export library") or "")
    function = str(_required_attr(
        info, "function", context="forwarded export function") or "")
    if not library or not function:
        raise ValueError(
            "forwarded export has an incomplete library/function target")
    return (library, function)


def _norm_lib(name: str) -> str:
    """Import/library names are case-insensitive to the Windows loader."""
    return (name or "").strip().lower()


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------

def read_exports(path: str | Path) -> Surface:
    """Parse the export directory of a PE image.

    `Surface.module` is the name recorded in the export directory when
    present — that is the name the linker burned in, and it is what a
    renamed original still reports — falling back to the file name.
    """
    binary = _parse(path)
    file_name = Path(path).name
    exports: dict[str, ExportEntry] = {}
    by_ordinal: dict[int, ExportEntry] = {}
    malformed: list[str] = []

    header = _required_attr(binary, "header", context="PE header")
    machine = _enum_name(_required_attr(
        header, "machine", context="PE machine type"))
    arch = _MACHINE_ARCH.get(machine)
    if not machine or arch is None:
        raise ValueError(
            f"unsupported or unreadable PE machine type in {file_name}: "
            f"{machine or '<empty>'}")

    export_dir = None
    has_exports = bool(_required_attr(
        binary, "has_exports", context="PE export-directory presence"))
    if has_exports:
        try:
            getter = _required_attr(
                binary, "get_export", context="PE export-directory getter")
            if not callable(getter):
                raise TypeError("get_export is not callable")
            export_dir = getter()
        except Exception as exc:               # noqa: BLE001
            raise ValueError(
                f"could not read export directory in {file_name}: "
                f"{type(exc).__name__}: {exc}") from exc
        if export_dir is None:
            raise ValueError(
                f"{file_name} reports exports but returned no export directory")

    if export_dir is None:
        module = file_name
        entries_list: list[Any] = []
    else:
        module = str(_required_attr(
            export_dir, "name", context="export-directory module name") or "")
        if not module:
            raise ValueError(
                f"export-directory module name is empty in {file_name}")
        raw_entries = _required_attr(
            export_dir, "entries", "it_entries",
            context="export-directory entries")
        try:
            entries_list = list(raw_entries)
        except Exception as exc:               # noqa: BLE001
            raise ValueError(
                f"could not enumerate exports in {file_name}: "
                f"{type(exc).__name__}: {exc}") from exc

    for index, raw in enumerate(entries_list):
        name = _required_attr(
            raw, "name", context=f"export entry {index} name")
        name = str(name) if name else ""
        try:
            ordinal = int(_required_attr(
                raw, "ordinal", context=f"export entry {index} ordinal"))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"export entry {index} has an unreadable ordinal") from exc
        try:
            rva = int(_required_attr(
                raw, "function_rva", "address", "value",
                context=f"export entry {index} RVA"))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"export entry {index} has an unreadable RVA") from exc
        try:
            forwarder = _forwarder_of(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"export {name or '<NONAME>'!r} at ordinal #{ordinal} has "
                f"unreadable forwarder metadata: {exc}") from exc
        if not name and not rva and forwarder is None:
            # A gap in the export address table (ordinal base 1, exports at
            # 4 and 7 => slots 5 and 6). Not a NONAME export; nothing to call.
            logger.debug("%s: skipping empty export slot #%d", file_name, ordinal)
            continue
        if not 1 <= ordinal <= 0xFFFF:
            malformed.append(f"export {name or '<NONAME>'!r} has unsupported "
                             f"ordinal {ordinal}")
        try:
            is_data = (False if forwarder is not None
                       else _looks_like_data(binary, rva))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"export {name or '<NONAME>'!r} at ordinal #{ordinal} has "
                f"unreadable code/data kind: {exc}") from exc
        entry = ExportEntry(
            name=name or None,
            ordinal=ordinal,
            rva=rva,
            forwarder=forwarder,
            # A forwarder's RVA points at the "dll.Func" string in .rdata,
            # so the section test would call every forwarder a data export.
            is_data=is_data,
        )
        key = export_key(entry)
        if key in exports:
            malformed.append(
                f"duplicate export key {key!r} at ordinals "
                f"{exports[key].ordinal} and {entry.ordinal}")
        exports[key] = entry
        if ordinal in by_ordinal:
            malformed.append(
                f"ordinal {ordinal} claimed twice by "
                f"{by_ordinal[ordinal].name!r} and {entry.name!r}")
        by_ordinal[ordinal] = entry

    if malformed:
        raise ValueError(f"malformed/ambiguous export table in {file_name}: "
                         + "; ".join(malformed))

    return Surface(module=module, arch=arch, exports=exports,
                   by_ordinal=by_ordinal, machine=machine,
                   path=str(path))


# --------------------------------------------------------------------------
# Imports (static + delay)
# --------------------------------------------------------------------------

def _blank_lib(raw_name: str) -> dict[str, Any]:
    return {
        "names": set(), "ordinals": set(), "delay": False, "static": False,
        "delay_names": set(), "delay_ordinals": set(), "raw_name": raw_name,
    }


def _absorb_entries(bucket: dict[str, Any], entries: Iterable[Any],
                    delay: bool) -> None:
    for raw in entries:
        if bool(_attr(raw, "is_ordinal", default=False)):
            try:
                ordinal = int(_attr(raw, "ordinal", default=0) or 0)
            except (TypeError, ValueError):
                continue
            bucket["ordinals"].add(ordinal)
            if delay:
                bucket["delay_ordinals"].add(ordinal)
            continue
        name = _attr(raw, "name", default="")
        name = str(name) if name else ""
        if not name:
            # Neither a name nor an ordinal flag: LIEF could not decode it.
            logger.debug("import entry with no name and no ordinal in %s",
                         bucket["raw_name"])
            continue
        bucket["names"].add(name)
        if delay:
            bucket["delay_names"].add(name)


def read_imports(path: str | Path) -> dict[str, dict]:
    """Imports of a PE image, keyed by lowercased library name.

    Each value is `{"names": set[str], "ordinals": set[int], "delay": bool,
    "static": bool, "delay_names": set[str], "delay_ordinals": set[int],
    "raw_name": str}`.

    Both the regular and the delay-load directory are read. A library that
    appears in both gets its symbols merged with `delay` and `static` both
    true; the `delay_*` subsets keep the merge lossless.
    """
    binary = _parse(path)
    libs: dict[str, dict] = {}

    for delay, attr_names in ((False, ("imports", "it_imports")),
                              (True, ("delay_imports", "it_delay_imports"))):
        descriptors = _attr(binary, *attr_names, default=[])
        for desc in descriptors:
            raw_name = str(_attr(desc, "name", default="") or "")
            if not raw_name:
                logger.warning("%s: %s import descriptor with no library name",
                               Path(path).name, "delay" if delay else "static")
                continue
            bucket = libs.setdefault(_norm_lib(raw_name), _blank_lib(raw_name))
            bucket["delay" if delay else "static"] = True
            _absorb_entries(bucket,
                            _attr(desc, "entries", "it_entries", default=[]),
                            delay)

    return libs


def required_surface(consumers: list[str],
                     target_dll: str) -> tuple[set[str], set[int]]:
    """Union of names and ordinals the consumers import from `target_dll`.

    This is the floor the shim must meet. Static and delay imports both
    count; a consumer that never mentions the target contributes nothing
    and is not an error (apps often ship optional plugins).
    """
    want = _norm_lib(Path(str(target_dll)).name)
    names: set[str] = set()
    ordinals: set[int] = set()
    failures: list[str] = []
    for consumer in consumers:
        try:
            libs = read_imports(consumer)
        except (FileNotFoundError, ValueError) as exc:
            failures.append(f"{consumer}: {exc}")
            continue
        bucket = libs.get(want)
        if bucket is None:
            logger.debug("%s does not import %s", consumer, want)
            continue
        names |= set(bucket["names"])
        ordinals |= set(bucket["ordinals"])
    if failures:
        raise ValueError("consumer PE inspection failed: " + "; ".join(failures))
    return names, ordinals


# --------------------------------------------------------------------------
# GetProcAddress suspects
# --------------------------------------------------------------------------

def _string_re(flavor: str, min_len: int) -> re.Pattern[bytes]:
    key = (flavor, min_len)
    cached = _STRING_RE_CACHE.get(key)
    if cached is None:
        unit = rb"[\x20-\x7e]" if flavor == "ascii" else rb"(?:[\x20-\x7e]\x00)"
        cached = re.compile(unit + b"{%d,}" % min_len)
        _STRING_RE_CACHE[key] = cached
    return cached


def _iter_strings(data: bytes, min_len: int) -> Iterator[str]:
    for m in _string_re("ascii", min_len).finditer(data):
        yield m.group().decode("ascii", "replace")
    for m in _string_re("utf16", min_len).finditer(data):
        yield m.group().decode("utf-16-le", "replace")


def scan_dynamic_candidates(consumer: str, surface: Surface,
                            *, min_len: int = 3) -> set[str]:
    """Exported names that appear as literal strings in the consumer.

    Names already bound through the import table are removed, so what is
    left is the set a `GetProcAddress` call could plausibly ask for. Static
    analysis of the import table alone cannot see these, and they are the
    reason a shim that satisfies `required_surface` can still be short.

    UTF-16LE is scanned as well as ASCII: `LoadLibraryW`-era code often
    keeps the whole name table wide even though `GetProcAddress` is ANSI.
    """
    exported = surface.names
    if not exported:
        return set()

    data = Path(consumer).read_bytes()
    hits: set[str] = set()
    for text in _iter_strings(data, min_len):
        if text in exported:
            hits.add(text)
            continue
        # A name can sit inside a larger literal (a format string, a merged
        # literal pool with no NUL between entries), so also try tokens.
        for token in _TOKEN_RE.findall(text):
            if token in exported:
                hits.add(token)

    try:
        libs = read_imports(consumer)
    except (FileNotFoundError, ValueError) as exc:
        logger.warning("%s: cannot read imports, not subtracting bound names: %s",
                       consumer, exc)
        return hits

    # The export directory name and the file name can differ (a renamed
    # original still reports its original name), so try both.
    bucket = libs.get(_norm_lib(surface.module))
    if bucket is None and surface.path:
        bucket = libs.get(_norm_lib(Path(surface.path).name))
    if bucket is not None:
        hits -= set(bucket["names"])
    return hits


# --------------------------------------------------------------------------
# Structural comparison
# --------------------------------------------------------------------------

def _as_surface(value: Surface | str | Path | None) -> Surface | None:
    if value is None or isinstance(value, Surface):
        return value
    return read_exports(value)


def compare_contract_surface(contract: Any,
                             original: Surface | str | Path) -> list[str]:
    """Require an exact, traceable Contract description of every export.

    A ``SymbolSpec`` describes a callable ABI.  It does *not* describe the
    storage, mutability, initialization or aliasing semantics of a data
    export, so a data export cannot be approved by pretending it is a
    function.  Likewise a pure ``forward`` entry bypasses the generated
    recording thunk.  Both states are rejected until dedicated evidence
    models exist for them.

    Named exports match by their case-sensitive loader name and explicit
    ordinal.  A NONAME export has no name to match, so its contract symbol is
    matched by explicit ordinal plus ``noname: true``.  Missing and surplus
    contract symbols both fail: otherwise an export could silently take the
    old untraced-forward path or a typo could create an invented surface.
    """
    orig = _as_surface(original)
    if orig is None:
        raise ValueError("compare_contract_surface needs an original surface")

    problems: list[str] = []
    module = str(getattr(contract, "module", "") or "")
    arch = str(getattr(contract, "arch", "") or "")
    symbols = getattr(contract, "symbols", None)
    if not isinstance(symbols, dict):
        return ["contract symbols are unavailable or malformed"]

    if not orig.module:
        problems.append("original export module name is unavailable")
    elif not module or orig.module.casefold() != module.casefold():
        problems.append(
            f"contract module {module!r} does not match original export "
            f"module {orig.module!r}")
    if not orig.arch or orig.arch == "unknown":
        problems.append("original export architecture is unavailable")
    elif arch != orig.arch:
        problems.append(
            f"contract arch {arch!r} does not match original {orig.arch!r}")

    claimed: dict[str, str] = {}
    for contract_name, sym in sorted(symbols.items()):
        ordinal = getattr(sym, "ordinal", None)
        noname = bool(getattr(sym, "noname", False))
        entry: ExportEntry | None = None

        if noname:
            if ordinal is None:
                problems.append(
                    f"contract symbol {contract_name!r} marks NONAME without "
                    "an explicit ordinal")
            else:
                entry = orig.by_ordinal.get(int(ordinal))
                if entry is None:
                    problems.append(
                        f"contract NONAME symbol {contract_name!r} at ordinal "
                        f"#{ordinal} is absent from the original")
                elif entry.name is not None:
                    problems.append(
                        f"contract symbol {contract_name!r} says ordinal "
                        f"#{ordinal} is NONAME, but the original exports it as "
                        f"{entry.name!r}")
                    entry = None
        else:
            entry = orig.exports.get(contract_name)
            if entry is None:
                problems.append(
                    f"contract symbol {contract_name!r} is absent from the "
                    "original export table")

        if entry is not None:
            key = export_key(entry)
            previous = claimed.get(key)
            if previous is not None:
                problems.append(
                    f"original export {key!r} is claimed by both contract "
                    f"symbols {previous!r} and {contract_name!r}")
            else:
                claimed[key] = contract_name
            if ordinal is None:
                problems.append(
                    f"contract symbol {contract_name!r} does not explicitly "
                    f"declare original ordinal #{entry.ordinal}")
            elif int(ordinal) != entry.ordinal:
                problems.append(
                    f"contract symbol {contract_name!r} declares ordinal "
                    f"#{ordinal}, original is #{entry.ordinal}")

        if getattr(sym, "forward", None):
            problems.append(
                f"contract symbol {contract_name!r} is a pure forward and "
                "bypasses trace recording")

    for key, entry in sorted(orig.exports.items()):
        if key not in claimed:
            label = (f"NONAME ordinal #{entry.ordinal}" if entry.name is None
                     else f"export {entry.name!r} at ordinal #{entry.ordinal}")
            problems.append(f"original {label} is missing from the contract")
        if entry.is_data is None:
            problems.append(
                f"original export {key!r} kind could not be classified as "
                "code or data")
        elif entry.is_data:
            problems.append(
                f"original data export {key!r} at ordinal #{entry.ordinal} "
                "is unverifiable by the callable SymbolSpec/trace model")
        if entry.forwarder is not None:
            problems.append(
                f"original forwarder {key!r} -> {entry.forwarder!r} cannot "
                "earn approval without a recorded call boundary")

    return problems


def compare_surface(generated: Surface | str | Path,
                    original: Surface | str | Path | None,
                    need_names: Iterable[str],
                    need_ords: Iterable[int]) -> list[str]:
    """Structural check of a generated tap/shim against the original DLL.

    Returns human-readable problem strings; empty means pass. Checked:

    * every required name is exported by `generated`
    * every required ordinal is exported by `generated`, and resolves to the
      same export the original put there
    * for every name both images export, the ordinal is identical
    * every NONAME export of the original is still NONAME at that ordinal
      (present, not renamed, not moved)
    * machine type matches

    `original` may be `None` when only the required floor is verifiable.
    """
    gen = _as_surface(generated)
    if gen is None:
        raise ValueError("compare_surface needs a generated surface")
    orig = _as_surface(original)
    problems: list[str] = []

    if orig is not None:
        if not gen.machine or not orig.machine:
            problems.append(
                f"machine type unavailable: generated={gen.machine or 'unknown'} "
                f"original={orig.machine or 'unknown'}")
        elif gen.machine != orig.machine:
            problems.append(
                f"machine mismatch: generated is {gen.machine}, "
                f"original is {orig.machine}")
        elif gen.arch != orig.arch:
            problems.append(
                f"arch mismatch: generated is {gen.arch}, original is {orig.arch}")

    for name in sorted(set(need_names)):
        if name not in gen.exports:
            problems.append(f"missing required export {name!r}")

    # Ordinals already called out below are not re-reported by the whole-map
    # passes; one defect should produce one line.
    reported: set[int] = set()
    for ordinal in sorted(set(int(o) for o in need_ords)):
        gen_entry = gen.by_ordinal.get(ordinal)
        orig_entry = orig.by_ordinal.get(ordinal) if orig else None
        if gen_entry is None:
            was = f" (original: {export_key(orig_entry)})" if orig_entry else ""
            problems.append(f"missing required ordinal #{ordinal}{was}")
            reported.add(ordinal)
            continue
        if orig_entry is not None and export_key(gen_entry) != export_key(orig_entry):
            problems.append(
                f"ordinal #{ordinal} resolves to {export_key(gen_entry)!r} in "
                f"generated but {export_key(orig_entry)!r} in original")
            reported.add(ordinal)

    if orig is None:
        return problems

    # Ordinal drift on a name nobody imports by ordinal today is still a
    # defect: GetProcAddress(MAKEINTRESOURCE(n)) is invisible to static
    # analysis, so the whole ordinal map has to hold, not just the floor.
    for key, orig_entry in sorted(orig.exports.items()):
        gen_entry = gen.exports.get(key)
        if gen_entry is None:
            # A NONAME export carries no name, so nothing else in this
            # function can notice it went missing: the required-name floor
            # has no name to look for and `scan_dynamic_candidates` has no
            # string to match. Its ordinal is the only handle it has.
            if orig_entry.name is None and orig_entry.ordinal not in reported:
                twin = gen.by_ordinal.get(orig_entry.ordinal)
                if twin is None:
                    problems.append(
                        f"NONAME export at ordinal #{orig_entry.ordinal} is "
                        f"missing from generated")
                elif twin.name is not None:
                    problems.append(
                        f"ordinal #{orig_entry.ordinal} is NONAME in original but "
                        f"exported as {twin.name!r} in generated")
            elif orig_entry.name is not None:
                problems.append(
                    f"original export {orig_entry.name!r} is missing from generated")
            continue
        if gen_entry.ordinal != orig_entry.ordinal:
            problems.append(
                f"export {key!r} moved from ordinal #{orig_entry.ordinal} to "
                f"#{gen_entry.ordinal}")
        if gen_entry.is_noname != orig_entry.is_noname:
            state = "NONAME" if orig_entry.is_noname else "named"
            problems.append(
                f"export {key!r} NONAME mismatch: original is {state}, "
                f"generated is not")
        if gen_entry.is_data is None or orig_entry.is_data is None:
            problems.append(
                f"export {key!r} kind unavailable: original="
                f"{orig_entry.is_data!r}, generated={gen_entry.is_data!r}")
        elif gen_entry.is_data != orig_entry.is_data:
            problems.append(
                f"export {key!r} kind mismatch: original is "
                f"{'data' if orig_entry.is_data else 'code'}, generated is "
                f"{'data' if gen_entry.is_data else 'code'}")
        if gen_entry.forwarder != orig_entry.forwarder:
            problems.append(
                f"export {key!r} forwarder mismatch: original="
                f"{orig_entry.forwarder!r}, generated={gen_entry.forwarder!r}")

    # An exact surface is safer than a superset: an unexpected name/ordinal is
    # observable through GetProcAddress and can accidentally expose a helper
    # entry point that the original DLL never made callable.
    for key in sorted(set(gen.exports) - set(orig.exports)):
        entry = gen.exports[key]
        problems.append(
            f"unexpected generated export {key!r} at ordinal #{entry.ordinal}")

    # A named export in `generated` sitting on an ordinal the original kept
    # NONAME is caught above; the reverse (named -> NONAME) shows up as a
    # missing required export only if someone imports it by name, so flag it
    # here while we still know both ordinal maps.
    for ordinal, orig_entry in sorted(orig.by_ordinal.items()):
        if orig_entry.name is None or ordinal in reported:
            continue
        gen_entry = gen.by_ordinal.get(ordinal)
        if gen_entry is not None and gen_entry.name is None:
            problems.append(
                f"export {orig_entry.name!r} at ordinal #{ordinal} became "
                f"NONAME in generated")

    return problems
