#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
checkpoint_scanner — passive abuse-indicator scanner for ML checkpoints.

READ-BYTES-ONLY FORENSICS. This tool:
  * NEVER executes, imports, torch.load()s, pickle.load()s or eval()s any
    scanned artifact.
  * Parses container metadata only (zip central directories and local file
    headers, tar headers, safetensors JSON header, numpy .npy headers).
  * Disassembles embedded pickle byte streams with `pickletools.genops`
    (a textual opcode walker — no path to desemantic execution exists).
  * Verifies CRC32 / SHA-256 by reading raw bytes, never by deserializing.

Formats: torch new-format zip (.pth/.pt/.ckpt), legacy raw-pickle save,
.npy / .npz (incl. object-dtype "allow_pickle" surfaces), .tar label banks,
safetensors, and generic media/text marker scans (polyglot indicators).

Checks per the project brief:
  1. Pickle opcode walk: GLOBAL/STACK_GLOBAL/INST/OBJ resolution against an
     allowlist; code-exec / network / process-spawn / native-bridge /
     stage-2 obfuscation / dynamic-import gadgets; REDUCE on flagged
     callables; opcodes after STOP; malformed or truncated opcode streams.
  2. String stashing inside pickles: base64-ish blobs, hex blobs,
     non-ASCII bytes, URLs.
  3. Container anomalies: encrypted entries, duplicate member names,
     nested archive markers inside members, inter-section gaps, member
     size mismatches, CRC mismatches, odd-sized data members.
  4. .npz/.npy object-dtype (allow_pickle) detection + globals of the
     embedded object pickle when present.
  5. Integrity: whole-file SHA-256 (local mode), per-member CRC32 (declared
     vs computed, byte-level). Remote-range mode retrieves only small
     ranges (EOCD/central directory/pickle members) over HTTP.

Verdict scale:
  CLEAN      only allowlisted globals (torch/numpy/declared project classes),
             no structural anomalies.
  SUSPICIOUS gadget-adjacent but benign-looking content: unusual modules
             reached through REDUCE, object-dtype labels, structural flags.
  WEAPONIZED an execution-capable gadget present (eval/exec/os.system/
             subprocess/socket/ctypes/stage-2 pickle/etc.).
  UNKNOWN    artifact could not be parsed reliably.

Output: one JSON per artifact under --out-dir (default ./scan_reports),
plus .dis disassembly text files under <out-dir>/disasm/.

Usage:
  python3 scanner.py FILE [FILE ...] [--out-dir DIR] [--no-sha] [--no-crc]
  python3 scanner.py URL [--url] --max-remote-pull 48   # range-based,
                                                        # pickle-only

Standard library only (Python >= 3.9). Point at untrusted files only from
an isolated, low-privilege account.
"""
import argparse
import ast
import hashlib
import io
import json
import os
import pickletools
import re
import struct
import sys
import tarfile
import time
import zlib
import zipfile

try:  # remote-range mode needs urllib; local mode must not fail without it
    import urllib.request
    import urllib.error
    HAVE_URLLIB = True
except Exception:  # pragma: no cover
    HAVE_URLLIB = False

SCAN_VERSION = "1.0.1 (Vesuvius passive-checkpoint-scan)"
USER_AGENT = "checkpoint-scanner/1.0 (passive; no model execution)"

# --------------------------------------------------------------------------
# Allowlists & gadget tables
# --------------------------------------------------------------------------

ALLOWED_PREFIXES = (
    "torch.", "torchaudio.", "torchvision.", "collections.", "numpy.",
    "np.", "safetensors.",
)

# Whole-module saves legitimately pickle project classes; recorded as
# "project_model_class" (info).
PROJECT_CLASS_RE = (
    r"^nnunetv2\.", r"^nnUNetTrainer", r"^nnunet\.",
    r"^networks\.", r"^dynamic_network_architectures\.", r"^monai\.",
    r"^vesuvius\.", r"^koine_machines\.", r"^segment_anything\.",
    r"^smp\.", r"^tta\.", r"^utils\.",
)

GADGET_MODULES = {
    "builtins": ("builtin_bad", 2, {
        "eval": ("code_exec", 2), "exec": ("code_exec", 2),
        "compile": ("code_exec", 2), "__import__": ("dynamic_import", 2),
        "open": ("file_exec", 1), "breakpoint": ("debug_hook", 1),
        "exit": ("process_control", 1),
    }),
    "__builtin__": ("builtin_bad", 2, {
        "eval": ("code_exec", 2), "exec": ("code_exec", 2),
        "open": ("file_exec", 1), "compile": ("code_exec", 2),
    }),
    "os": ("os_family", 1, {
        "system": ("code_exec", 2), "popen": ("code_exec", 2),
        "execv": ("code_exec", 2), "execve": ("code_exec", 2),
        "execvp": ("code_exec", 2), "execvpe": ("code_exec", 2),
        "spawnl": ("code_exec", 2), "spawnv": ("code_exec", 2),
        "spawnlp": ("code_exec", 2), "spawnve": ("code_exec", 2),
    }),
    "posix": ("os_family", 1, {
        "system": ("code_exec", 2), "popen": ("code_exec", 2),
        "execv": ("code_exec", 2),
    }),
    "nt": ("os_family", 1, {
        "system": ("code_exec", 2), "popen": ("code_exec", 2),
    }),
    "subprocess": ("process_exec", 2, {}),
    "multiprocessing": ("process_exec", 2, {}),
    "socket": ("network", 2, {}),
    "ctypes": ("native_bridge", 2, {}),
    "urllib": ("network", 2, {}),
    "urllib.request": ("network", 2, {}),
    "urllib3": ("network", 2, {}),
    "http": ("network", 2, {}),
    "http.client": ("network", 2, {}),
    "ftplib": ("network", 2, {}),
    "smtplib": ("network", 2, {}),
    "telnetlib": ("network", 2, {}),
    "xmlrpc": ("network", 2, {}),
    "requests": ("network", 2, {}),
    "httpx": ("network", 2, {}),
    "aiohttp": ("network", 2, {}),
    "websockets": ("network", 2, {}),
    "marshal": ("obfuscation", 2, {}),
    "base64": ("obfuscation", 1, {
        "b64decode": ("obfuscation", 2), "b64encode": ("obfuscation", 1),
    }),
    "binascii": ("obfuscation", 1, {
        "a2b_base64": ("obfuscation", 2), "a2b_hex": ("obfuscation", 1),
    }),
    "codecs": ("obfuscation", 1, {
        "decode": ("obfuscation", 2), "encode": ("obfuscation", 2),
    }),
    "zlib": ("obfuscation", 1, {"decompress": ("obfuscation", 1)}),
    "gzip": ("obfuscation", 1, {"decompress": ("obfuscation", 1)}),
    "bz2": ("obfuscation", 1, {"decompress": ("obfuscation", 1)}),
    "lzma": ("obfuscation", 1, {"decompress": ("obfuscation", 1)}),
    "pickle": ("stage2_pickle", 2, {"loads": ("stage2_pickle", 2),
                                    "load": ("stage2_pickle", 2)}),
    "_pickle": ("stage2_pickle", 2, {}),
    "dill": ("stage2_pickle", 2, {}),
    "shutil": ("fs_mutate", 1, {}),
    "importlib": ("dynamic_import", 2, {}),
    "importlib.util": ("dynamic_import", 2, {}),
    "runpy": ("code_exec", 2, {}),
    "tempfile": ("fs_exec", 1, {"mktemp": ("fs_exec", 2)}),
    "pathlib": ("fs_access", 1, {}),
    "io": ("io", 1, {"open": ("file_exec", 1)}),
    "sys": ("introspection", 1, {}),
    "gc": ("introspection", 1, {}),
    "inspect": ("introspection", 1, {}),
    "time": ("benign_stdlib", 0, {}),
    "re": ("benign_stdlib", 0, {}),
    "struct": ("benign_stdlib", 0, {}),
    "copy": ("benign_stdlib", 0, {}),
    "json": ("benign_stdlib", 0, {}),
    "functools": ("benign_stdlib", 0, {}),
}
BENIGN_ALONE = {"torch", "collections", "numpy", "np", "builtins", "copy"}

BENIGN_BUILTINS = {
    "len", "range", "int", "float", "str", "bytes", "bytearray", "dict",
    "list", "set", "frozenset", "tuple", "map", "zip", "bool", "abs",
    "min", "max", "sum", "round", "iter", "repr", "hash", "ord", "chr",
}


def classify_global(module, name):
    """Return (category, severity, detail) for a resolved pickle global."""
    if module is None:
        return ("unresolved", 1, "could not resolve stack-global target")
    dotted = (module + "." + (name or "")).rstrip(".")
    if dotted.startswith(ALLOWED_PREFIXES):
        return ("torch_ecosystem_allowlist", 0, "")
    top = module.split(".")[0]
    mod = module if module in GADGET_MODULES else (
        top if top in GADGET_MODULES else None)
    if mod is not None:
        dcat, dsev, table = GADGET_MODULES[mod]
        if mod in ("torch", "collections", "numpy"):
            return ("torch_ecosystem_allowlist", 0, "")
        if mod in ("builtins", "__builtin__"):
            if name in table:
                cat, sev = table[name]
                return (cat, sev, "gadget builtins.%s" % name)
            if name in BENIGN_BUILTINS:
                return ("builtin_container_ctor", 0, "")
            return ("builtins_other", 1, "builtins.%s" % name)
        if name in table:
            cat, sev = table[name]
            return (cat, sev, "%s.%s" % (mod, name))
        return (dcat, max(1, dsev), "stdlib gadget module %s (name=%s)" % (
            mod, name))
    if not name:
        if module in BENIGN_ALONE:
            return ("torch_ecosystem_allowlist", 0, "")
        return ("module_ref", 1, "bare module reference %s" % module)
    for pat in PROJECT_CLASS_RE:
        if re.match(pat, module):
            return ("project_model_class", 0, dotted)
    return ("nonstandard_module", 1, "unexpected module %s (name=%s)" % (
        module, name))


# --------------------------------------------------------------------------
# Pickle analysis — pure opcode walk, no ever-executable semantics
# --------------------------------------------------------------------------

_PUSHSTR_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
                "SHORT_BINSTRING", "BINSTRING", "BINBYTES", "BINBYTES8",
                "SHORT_BINBYTES", "BYTEARRAY8", "BINBYTES16"}

_BASE64ISH = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")
_HEXISH = re.compile(r"^[0-9a-fA-F]{64,}$")
_URLISH = re.compile(r"^(https?|ftp|wss?|file|data)://", re.I)

TOP_STRINGS_CAP = 8000


def hexdump(buf, base=0, limit=4096, width=16):
    lines = []
    view = buf[:limit]
    for off in range(0, len(view), width):
        chunk = view[off:off + width]
        hexs = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08x  %-46s  %s" % (base + off, hexs, text))
    return "\n".join(lines)


class PickleAnalysis(object):
    """Static opcode walk over raw pickle bytes. Nothing is executed or
    imported as a result of analysis."""

    def __init__(self, label, pickle_bytes, base_offset=0, entry_name=None):
        self.label = label
        self.entry_name = entry_name or label
        self.buf = bytes(pickle_bytes)
        self.base_offset = base_offset
        self.protocol = None
        self.opcodes_total = 0
        self.histogram = {}
        self.stop_offset = None
        self.trailing_bytes = 0
        self.globals = []
        self.reduce_on_flagged = []
        self.strings = 0
        self.string_flags = []
        self.top_strings = []
        self.error = None
        self._pending_globs = []

    # ---- helpers ----
    def _abs(self, pos):
        return (self.base_offset or 0) + pos

    def flag_string(self, kind, value, pos, extra=""):
        self.string_flags.append({
            "kind": kind,
            "pos_in_pickle": pos,
            "abs_offset": self._abs(pos),
            "length": len(value),
            "preview_short": value[:72],
            "detail": extra,
            "context_hex": hexdump(
                self.buf[max(0, pos - 16):pos + len(value[:120]) + 16],
                base=self._abs(max(0, pos - 16)), limit=200),
        })

    # ---- main ----
    def analyze(self):
        buf = self.buf
        if not buf:
            self.error = "empty pickle buffer"
            return self
        if buf[0] in (0x80, 0x8A) and len(buf) > 1:
            self.protocol = buf[1]
        try:
            str_window = []
            for op, arg, pos in pickletools.genops(buf):
                name = getattr(op, "name", str(op))
                self.opcodes_total += 1
                self.histogram[name] = self.histogram.get(name, 0) + 1
                if name == "STOP":
                    self.stop_offset = pos
                    break
                if name in _PUSHSTR_OPS:
                    self.strings += 1
                    if isinstance(arg, bytes):
                        try:
                            sv = arg.decode("utf-8")
                        except UnicodeDecodeError:
                            sv = arg.decode("latin-1")
                    else:
                        sv = str(arg)
                    str_window.append((sv, pos))
                    if len(str_window) > 4:
                        str_window.pop(0)
                    if len(self.top_strings) < TOP_STRINGS_CAP and \
                            len(sv) <= 512:
                        self.top_strings.append(sv)
                    printable = True
                    if len(sv) < 4096:
                        printable = all(32 <= ord(c) < 127 or c in "\n\t\r"
                                        for c in sv)
                    if not printable:
                        self.flag_string("non_ascii_binary", sv, pos,
                                         "non-printable bytes inside string")
                    elif _HEXISH.match(sv):
                        self.flag_string("hex_blob", sv, pos,
                                         "hex-shaped blob, len=%d" % len(sv))
                    elif _BASE64ISH.match(sv) and len(sv) >= 48:
                        is_path = sv.startswith(("/", "./", "..", "\\")
                                                ) or re.match(
                            r"^[A-Za-z]:[\\/]", sv)
                        if not is_path:
                            self.flag_string("base64_ish", sv, pos,
                                             "base64-shaped blob, len=%d"
                                             % len(sv))
                    if _URLISH.match(sv):
                        self.flag_string("url_string", sv, pos, "")
                    continue
                if name in ("GLOBAL", "INST", "OBJ"):
                    module, gname = None, None
                    if isinstance(arg, str):
                        parts = re.split(r"[\s\n]+", arg.strip())
                        module = parts[0] if parts else None
                        gname = parts[1] if len(parts) > 1 else ""
                    self._record_global(module, gname, name, pos, opcode_str=arg)
                    continue
                if name == "STACK_GLOBAL":
                    if len(str_window) >= 2:
                        gname, _gp = str_window[-1]
                        module, _mp = str_window[-2]
                        self._record_global(
                            module, gname, name, pos,
                            opcode_str="(from stack strings)")
                    else:
                        self._record_global(None, None, name, pos,
                                            "(unresolvable)")
                    if len(str_window) >= 2:
                        str_window.pop()
                        str_window.pop()
                    continue
                if name in ("NEWOBJ", "NEWOBJ_EX"):
                    if len(str_window) >= 2:
                        module = str_window[-2][0]
                        gname = str_window[-1][0]
                        self._record_global(module, gname, name, pos,
                                            "(newobj)")
                    continue
                if name == "REDUCE":
                    if self._pending_globs:
                        pending = self._pending_globs[-1]
                        if pending.get("severity", 0) > 0:
                            self.reduce_on_flagged.append({
                                "pos_in_pickle": pos,
                                "abs_offset": self._abs(pos),
                                "called": pending.get("dotted"),
                                "called_category": pending.get("category"),
                                "called_severity": pending.get("severity"),
                            })
                        if self._pending_globs:
                            self._pending_globs.pop()
            if self.stop_offset is not None:
                self.trailing_bytes = len(buf) - (self.stop_offset + 1)
        except Exception as e:  # malformed opcode stream
            self.error = "%s: %s" % (type(e).__name__, e)
        return self

    def _record_global(self, module, gname, opname, pos, opcode_str=""):
        cat, sev, note = classify_global(module, gname)
        g = {
            "opcode": opname,
            "module": module,
            "name": gname,
            "dotted": ((module or "?") + "." + (gname or "?")).rstrip("."),
            "category": cat,
            "severity": sev,
            "pos_in_pickle": pos,
            "abs_offset": self._abs(pos),
            "detail": (opcode_str or "") + ((" " + note) if note else ""),
            "context_hex": hexdump(
                self.buf[max(0, pos - 16):pos + 96],
                base=self._abs(max(0, pos - 16)), limit=160),
        }
        self.globals.append(g)
        self._pending_globs.append(g)

    def to_dict(self):
        cats = {}
        for g in self.globals:
            cats[g["category"]] = cats.get(g["category"], 0) + 1
        return {
            "entry": self.entry_name,
            "label": self.label,
            "protocol": self.protocol,
            "pickle_size": len(self.buf),
            "pickle_byte_range": [self.base_offset,
                                  self.base_offset + len(self.buf) - 1],
            "opcode_count": self.opcodes_total,
            "histogram_top": sorted(self.histogram.items(),
                                    key=lambda kv: -kv[1])[:20],
            "stop_offset_in_pickle": self.stop_offset,
            "trailing_bytes_after_stop": self.trailing_bytes,
            "string_constants": self.strings,
            "string_flags": self.string_flags,
            "unique_global_refs": sorted({
                g["dotted"] for g in self.globals if g["module"]
            }),
            "global_category_counts": cats,
            "globals_flagged": [
                {k: g[k] for k in ("opcode", "module", "name", "dotted",
                                   "category", "severity", "pos_in_pickle",
                                   "abs_offset", "detail", "context_hex")}
                for g in self.globals if g["severity"] > 0
            ],
            "reduce_on_flagged": self.reduce_on_flagged,
            "error": self.error,
        }


def disassemble_to_text(buf):
    out = io.StringIO()
    try:
        pickletools.dis(io.BytesIO(buf), out)
        return out.getvalue()
    except Exception as e:
        return "!! disassembly aborted: %s: %s" % (type(e).__name__, e)


def _flags_from_pickle(pa, label):
    """Flatten a PickleAnalysis into anomaly rows (deduped/aggregated)."""
    flags = []
    seen = {}
    for g in pa.globals:
        if g["severity"] == 0:
            continue
        key = (g["severity"], g["dotted"])
        if key not in seen:
            seen[key] = True
            flags.append({"id": "pickle_global", "severity": g["severity"],
                          "detail": "%s: %s [%s] %s"
                                    % (label, g["dotted"], g["category"],
                                       "deadly gadget" if g["severity"] >= 2
                                       else "suspicious"),
                          "abs_offset": g["abs_offset"]})
    aggr = {}
    for f in pa.string_flags:
        key = (f["kind"], f["preview_short"][:16])
        if key not in aggr:
            aggr[key] = [1, f]
        else:
            aggr[key][0] += 1
    for (k, _), (n, f) in list(aggr.items())[:8]:
        flags.append({"id": "pickle_string_%s" % k, "severity": 1,
                      "detail": "%s: %s, %d occurrences (first shown; "
                                "usually tensor bytes under latin-1/utf-8 "
                                "legacy storage encoding)"
                                % (label, k, n),
                      "abs_offset": f["abs_offset"],
                      "preview": f["preview_short"][:32]})
    extra = len(aggr) - 8
    if extra > 0:
        flags.append({"id": "pickle_string_more_kinds", "severity": 1,
                      "detail": "%s: %d further distinct flagged-string "
                                "kinds" % (label, extra),
                      "abs_offset": None})
    if pa.trailing_bytes:
        flags.append({"id": "pickle_trailing_bytes", "severity": 1,
                      "detail": "%s: %d bytes after STOP"
                                % (label, pa.trailing_bytes),
                      "abs_offset": pa._abs(pa.stop_offset + 1)})
    if pa.stop_offset is None and not pa.error:
        flags.append({"id": "pickle_no_stop", "severity": 1,
                      "detail": "%s: no STOP opcode found" % label,
                      "abs_offset": None})
    return flags


# --------------------------------------------------------------------------
# numpy .npy
# --------------------------------------------------------------------------

DTYPE_OBJECT_TOKEN = re.compile(r"(^|[|,(<\s])O(?![a-zA-Z0-9])")


def parse_npy(buf, label, base_offset=0):
    info = {"label": label, "format": "npy", "ok": False}
    try:
        if len(buf) < 10 or buf[:6] != b"\x93NUMPY":
            info["note"] = "not a .npy stream"
            return info
        major, minor = struct.unpack("<BB", buf[6:8])
        if major == 1:
            hlen = struct.unpack("<H", buf[8:10])[0]
            hstart = 10
        elif major in (2, 3):
            hlen = struct.unpack("<I", buf[8:12])[0]
            hstart = 12
        else:
            info["note"] = "unknown npy major version %d" % major
            return info
        hdr = buf[hstart:hstart + hlen]
        info["header_len"] = hlen
        info["data_abs_offset"] = (base_offset or 0) + hstart + hlen
        try:
            meta = ast.literal_eval(hdr.decode("utf-8").strip())
        except Exception as e:
            info["note"] = "unparseable header (%s: %s)" % (
                type(e).__name__, e)
            return info
        info["descr"] = meta.get("descr")
        info["shape"] = meta.get("shape")
        info["fortran_order"] = meta.get("fortran_order")
        info["header_keys"] = sorted(meta.keys())
        descr = info["descr"]
        obj = False
        if isinstance(descr, str):
            obj = bool(DTYPE_OBJECT_TOKEN.search(descr)) or descr == "O"
        else:
            try:
                fl = json.dumps(descr)
                obj = bool(re.search(r"([|,(<\s'\"])O(?![a-zA-Z0-9])", fl))
            except Exception:
                pass
        info["object_dtype"] = obj
        info["allow_pickle_surface"] = bool(obj)
        if obj:
            info["embedded_pickle"] = PickleAnalysis(
                label + "::object-payload",
                buf[hstart + hlen:],
                (base_offset or 0) + hstart + hlen
            ).analyze().to_dict()
        info["ok"] = True
    except Exception as e:
        info["error"] = "%s: %s" % (type(e).__name__, e)
    return info


def parse_safetensors(buf, label):
    info = {"format": "safetensors", "label": label, "ok": False}
    try:
        if len(buf) < 8:
            info["error"] = "too small"
            return info
        (hlen,) = struct.unpack("<Q", buf[:8])
        info["header_len"] = hlen
        if hlen > 100 * 1024 * 1024:
            info["error"] = "absurd header length %d" % hlen
            return info
        hdr = json.loads(buf[8:8 + hlen].decode("utf-8"))
        info["metadata"] = hdr.pop("__metadata__", None)
        info["tensor_count"] = len(hdr)
        info["dtypes"] = sorted({v.get("dtype") for v in hdr.values()
                                 if isinstance(v, dict) and v.get("dtype")})
        info["ok"] = True
    except Exception as e:
        info["error"] = "%s: %s" % (type(e).__name__, e)
    return info


# --------------------------------------------------------------------------
# zip container analysis
# --------------------------------------------------------------------------

STORAGE_TYPE_ELEMSIZE = {
    "torch.FloatStorage": 4, "torch.HalfStorage": 2,
    "torch.BFloat16Storage": 2, "torch.DoubleStorage": 8,
    "torch.IntStorage": 4, "torch.LongStorage": 8, "torch.ShortStorage": 2,
    "torch.CharStorage": 1, "torch.ByteStorage": 1, "torch.BoolStorage": 1,
    "torch.ComplexFloatStorage": 8, "torch.ComplexDoubleStorage": 16,
}


def zip_entry_inventory(zf, crc_check=True, crc_cap_mb=1600):
    entries, anomalies = [], []
    seen = set()
    for zi in zf.infolist():
        flags = zi.flag_bits
        e = {
            "name": zi.filename,
            "file_size": zi.file_size,
            "compress_size": zi.compress_size,
            "compress_type": {0: "STORED", 8: "DEFLATED"}.get(
                zi.compress_type, str(zi.compress_type)),
            "crc_hex": "0x%08x" % (zi.CRC & 0xffffffff),
            "flag_bits": flags,
            "encrypted": bool(flags & 0x1),
            "aes_extra_flag": bool(flags & 0x40),
            "data_descriptor": bool(flags & 0x8),
            "header_offset": zi.header_offset,
        }
        if e["encrypted"] or e["aes_extra_flag"]:
            anomalies.append({"id": "encrypted_entry", "severity": 2,
                              "byte_offset": zi.header_offset,
                              "detail": "member %s is encrypted"
                                        % zi.filename})
        if zi.filename in seen:
            anomalies.append({"id": "duplicate_member_name", "severity": 1,
                              "byte_offset": zi.header_offset,
                              "detail": "duplicate member %s"
                                        % zi.filename})
        seen.add(zi.filename)
        entries.append(e)
    if crc_check:
        for zi, e in zip(zf.infolist(), entries):
            if e["file_size"] > crc_cap_mb * 1024 * 1024:
                anomalies.append({
                    "id": "crc_skipped_size", "severity": 0,
                    "byte_offset": zi.header_offset,
                    "detail": "CRC check skipped for %s (> %dMB)"
                              % (zi.filename, crc_cap_mb)})
                continue
            try:
                crc, total = 0, 0
                with zf.open(zi, "r") as fh:
                    while True:
                        b = fh.read(256 * 1024)
                        if not b:
                            break
                        crc = zlib.crc32(b, crc)
                        total += len(b)
                crc &= 0xffffffff
                if total != e["file_size"]:
                    anomalies.append({
                        "id": "size_mismatch_header_vs_stream", "severity": 1,
                        "byte_offset": zi.header_offset,
                        "detail": "%s declared %d bytes, stream yielded %d"
                                  % (zi.filename, e["file_size"], total)})
                elif crc != (zi.CRC & 0xffffffff):
                    anomalies.append({
                        "id": "crc_mismatch", "severity": 2,
                        "byte_offset": zi.header_offset,
                        "detail": "%s declared CRC %s but bytes have %s"
                                  % (zi.filename,
                                     "0x%08x" % (zi.CRC & 0xffffffff),
                                     "0x%08x" % crc)})
            except zipfile.BadZipFile as e0:
                anomalies.append({"id": "corrupt_member", "severity": 2,
                                  "byte_offset": zi.header_offset,
                                  "detail": "%s: %s" % (zi.filename, e0)})
            except Exception as e1:
                anomalies.append({"id": "member_read_error", "severity": 1,
                                  "byte_offset": zi.header_offset,
                                  "detail": "%s: %s" % (zi.filename, e1)})
    return entries, anomalies


def embedded_archive_markers(buf, base_offset=0, restricted=False):
    flags = []
    if restricted:
        # scanning the *inside* of known containers (e.g. pickle members):
        # fragile short magics (MZ, \\x80\\x02 pickle markers) appear
        # coincidentally or legitimately, so only durable signatures.
        kinds = ((b"PK\x03\x04", "zip_local_header"),
                 (b"PK\x01\x02", "zip_central_header"),
                 (b"PK\x05\x06", "zip_eocd"),
                 (b"\x93NUMPY", "numpy_stream"),
                 (b"\x7fELF", "elf_header"))
    else:
        kinds = ((b"PK\x03\x04", "zip_local_header"),
                 (b"PK\x01\x02", "zip_central_header"),
                 (b"PK\x05\x06", "zip_eocd"),
                 (b"\x93NUMPY", "numpy_stream"),
                 (b"\x7fELF", "elf_header"),
                 (b"MZ", "pe_header"),
                 (b"\x80\x02", "pickle_proto2"),
                 (b"\x80\x04", "pickle_proto4"))
    for magic, kind in kinds:
        idx = buf.find(magic)
        if idx >= 0:
            flags.append({"kind": kind, "offset_in_member": idx,
                          "abs_offset": base_offset + idx})
    if b"#!/" in buf[:512]:
        flags.append({"kind": "shebang", "offset_in_member": 0,
                      "abs_offset": base_offset})
    for tag in (b"eval(", b"exec(", b"<script"):
        j = buf.find(tag)
        if j >= 0:
            flags.append({"kind": "text_pattern_%s"
                          % tag.decode("ascii", "ignore"),
                          "offset_in_member": j,
                          "abs_offset": base_offset + j})
    return flags


def aggregate_string_flags(flags, max_unique=10):
    """Collapse repeats of identical (kind, preview) flags into one row."""
    out, seen = [], {}
    for f in flags:
        key = (f.get("kind"), (f.get("preview_short") or "")[:24])
        if key in seen:
            seen[key][0] += 1
        else:
            seen[key] = [1, f]
    for (k, _), (n, f) in list(seen.items())[:max_unique]:
        f2 = dict(f)
        f2["occurrences"] = n
        out.append(f2)
    overflow = len(seen) - max_unique
    if overflow > 0:
        out.append({"kind": "string_flag_more_kinds",
                    "detail": "%d additional distinct flagged-string kinds "
                              "suppressed" % overflow,
                    "occurrences": None})
    return out


def analyze_torch_zip(zf, crc_check=True, dis_dir=None, dis_prefix=""):
    entries, anomalies = zip_entry_inventory(zf, crc_check=crc_check)
    pickle_members = []
    data_members = []
    for e in entries:
        lowname = e["name"].lower()
        if e["name"].endswith("/"):
            continue
        if lowname.endswith(".pkl") or lowname.endswith(".pickle"):
            pickle_members.append(e)
        else:
            data_members.append(e)
    if not pickle_members:
        for e in entries:
            if e["file_size"] and e["file_size"] < 8 * 1024 * 1024 and \
                    not e["name"].endswith("/"):
                pickle_members.append(e)
    pickle_scans = []
    if dis_dir is not None:
        try:
            os.makedirs(dis_dir, exist_ok=True)
        except Exception:
            dis_dir = None
    for pm in pickle_members:
        try:
            raw = zf.read(pm["name"])
            pa = PickleAnalysis(pm["name"], raw, 0).analyze()
            d = pa.to_dict()
            pickle_scans.append(d)
            if dis_dir is not None:
                try:
                    base = _safe_name(pm["name"]) + ".dis"
                    if dis_prefix:
                        base = (_safe_name(dis_prefix)[:76] + "__" +
                                _safe_name(pm["name"])[:96] + ".dis")
                    p = os.path.join(dis_dir, base)
                    with open(p, "w", encoding="utf-8", errors="replace") as fh:
                        fh.write(disassemble_to_text(raw))
                    d["disassembly_file"] = p
                except Exception as e:
                    d["disassembly_error"] = str(e)
            marked = embedded_archive_markers(raw, 0, restricted=True)
            if marked:
                d["marked_payloads"] = marked
            for f in marked:
                if f["kind"] in ("zip_local_header", "zip_eocd",
                                 "elf_header"):
                    anomalies.append({
                        "id": "embedded_archive_in_pickle_member",
                        "severity": 2,
                        "detail": "member %s contains %s"
                                  % (pm["name"], f["kind"])})
            anomalies.extend(_flags_from_pickle(pa, pm["name"]))
            if pa.opcodes_total > 900000:
                anomalies.append({
                    "id": "pickle_opcode_count_high", "severity": 0,
                    "detail": "%s has %d opcodes" % (pm["name"],
                                                     pa.opcodes_total)})
        except Exception as e:
            anomalies.append({"id": "pickle_member_parse_error",
                              "severity": 1,
                              "detail": "%s: %s" % (pm["name"], e)})
    integer_members = [e["name"] for e in data_members
                       if re.match(r"^\d+(_[a-z]+)?$", os.path.basename(
                           e["name"]))] if data_members else []
    if integer_members:
        anomalies.append({
            "id": "note_numeric_storage_members", "severity": 0,
            "detail": "%d numeric-keyed storage members (torch tensor "
                      "payloads): %d data members total" % (
                          len(integer_members), len(data_members))})
    odd_entries = [e["name"] for e in data_members
                   if e["file_size"] % 2 == 1 and e["file_size"] > 8]
    if odd_entries:
        anomalies.append({
            "id": "odd_sized_data_members", "severity": 1,
            "detail": "odd byte sizes among data members: %s"
                      % ", ".join(odd_entries[-6:])})
    return {
        "format": "torch_zip",
        "zip_comment": (zf.comment.decode("utf-8", "replace")
                        if zf.comment else ""),
        "member_count": len(entries),
        "entries": entries,
        "pickle_members": pickle_scans,
        "data_member_count": len(data_members),
        "anomalies": anomalies,
    }


def _safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[-120:] or "root"


# --------------------------------------------------------------------------
# tar label-bank scanning (headers only)
# --------------------------------------------------------------------------

PICKLE_MAGIC_BYTES = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05",
                      b"\x80\x01")


def scan_tar(path_or_fd, data=None, max_member_read=32 * 1024 * 1024):
    info = {"format": "tar", "members": [], "anomalies": []}
    try:
        tf = tarfile.open(data if data is not None else path_or_fd, "r:*")
    except Exception as e:
        info["error"] = "tar open failed: %s: %s" % (type(e).__name__, e)
        return info
    try:
        members = tf.getmembers()
    except Exception as e:
        info["error"] = "tar header walk failed: %s: %s" % (
            type(e).__name__, e)
        return info
    info["member_count"] = len(members)
    dir_count = 0
    pickled_members = []
    tiny_pickle_hits = []
    for m in members:
        ent = {"name": m.name,
               "type": "dir" if m.isdir() else ("file" if m.isfile()
                                                else "other"),
               "size": m.size}
        if m.isdir():
            dir_count += 1
        if m.isdir() or m.issym() or m.islnk() or m.isdev():
            if m.issym() or m.islnk() or m.isdev():
                info["anomalies"].append({
                    "id": "tar_special_member", "severity": 1,
                    "detail": "%s is link/device/special" % m.name})
            elif m.name.startswith("/") or ".." in m.name.split("/"):
                info["anomalies"].append({
                    "id": "tar_traversal_path", "severity": 1,
                    "detail": "%s is absolute/parent traversal" % m.name})
            info["members"].append(ent)
            continue
        nm = m.name.lower()
        if nm.endswith((".json", ".zarray", ".zattrs")) and \
                m.size <= 8 * 1024 * 1024:
            try:
                fobj = tf.extractfile(m)
                if fobj is not None:
                    raw = fobj.read()
                    try:
                        j = json.loads(raw.decode("utf-8"))
                        if nm.endswith(".zarray"):
                            ent["dtype"] = j.get("dtype")
                            ent["object_codec"] = j.get("object_codec")
                            if ent["object_codec"]:
                                info["anomalies"].append({
                                    "id": "zarr_object_codec", "severity": 1,
                                    "detail": "%s declares object_codec=%s"
                                              % (m.name,
                                                 ent["object_codec"])})
                        else:
                            ent["json_keys"] = sorted(j.keys())[:12]
                    except Exception as e2:
                        ent["json_error"] = str(e2)
            except Exception as ex:
                ent["read_error"] = str(ex)
        elif nm.endswith((".pkl", ".pickle")) and m.size <= max_member_read:
            try:
                fobj = tf.extractfile(m)
                raw = fobj.read()
                pa = PickleAnalysis(m.name, raw, 0).analyze()
                ent["pickle_scan"] = pa.to_dict()
                pickled_members.append(pa)
                info["anomalies"].extend(_flags_from_pickle(pa, m.name))
            except Exception as ex:
                ent["read_error"] = str(ex)
        elif nm.endswith(".npy") and m.size <= max_member_read:
            try:
                fobj = tf.extractfile(m)
                raw = fobj.read()
                info_an = parse_npy(raw, m.name)
                ent["npy_scan"] = info_an
                if info_an.get("embedded_pickle"):
                    for g in info_an["embedded_pickle"].get(
                            "globals_flagged", []):
                        info["anomalies"].append({
                            "id": "npy_object_pickle_global",
                            "severity": g.get("severity", 1),
                            "detail": "%s %s" % (m.name, g["dotted"])})
            except Exception as ex:
                ent["read_error"] = str(ex)
        elif m.size <= 4096:
            try:
                fobj = tf.extractfile(m)
                raw = fobj.read()
                if raw[:1] == b"\x80" and raw[:2] in PICKLE_MAGIC_BYTES:
                    pa = PickleAnalysis("tiny::" + m.name, raw,
                                        0).analyze()
                    tiny_pickle_hits.append(pa)
                    ent["clearly_contains_pickle_payload"] = True
                    info["anomalies"].extend(_flags_from_pickle(
                        pa, "tiny::" + m.name))
            except Exception:
                pass
        info["members"].append(ent)
    info["directories"] = dir_count
    info["flagged_members_summary"] = {
        "pickle_members": [p.label for p in pickled_members],
        "tiny_pickle_hits": [p.label for p in tiny_pickle_hits],
    }
    return info


# --------------------------------------------------------------------------
# remote range scanning (EOCD + CD + pkl members only)
# --------------------------------------------------------------------------

class RemoteRange(object):
    def __init__(self, url, max_pull_bytes=48 * 1024 * 1024):
        if not HAVE_URLLIB:
            raise RuntimeError("urllib unavailable; remote mode disabled")
        self.url = url
        self.max_pull = max_pull_bytes
        self.pulled = 0
        self._opener = urllib.request.build_opener()

    def _fetch(self, start, end, what):
        if start > end:
            raise RuntimeError("bad range %d-%d" % (start, end))
        need = end - start + 1
        if self.pulled + need > self.max_pull:
            raise RuntimeError(
                "remote retrieval cap (%d bytes) reached; refusing further "
                "pull" % self.max_pull)
        req = urllib.request.Request(self.url, headers={
            "User-Agent": USER_AGENT,
            "Range": "bytes=%d-%d" % (start, end)})
        with self._opener.open(req, timeout=90) as resp:
            code = resp.status
            content_range = resp.headers.get("Content-Range")
            data = resp.read()
        self.pulled += len(data)
        if not content_range:
            raise RuntimeError(
                "host ignored Range for %s (HTTP %s); range mode requires a "
                "range-capable host" % (what, code))
        return data

    def probe_size(self):
        req = urllib.request.Request(self.url, headers={
            "User-Agent": USER_AGENT, "Range": "bytes=0-0"})
        with self._opener.open(req, timeout=60) as r:
            cl = int(r.headers.get("Content-Length", "0") or 0)
            cr = r.headers.get("Content-Range", "")
            linked = r.headers.get("X-Linked-Size")
        total = None
        if cr and "/" in cr:
            tr = cr.rsplit("/", 1)[1].strip()
            if tr and tr != "*":
                total = int(tr)
        elif linked:
            total = int(linked)
        if not total and cl and cr == "":
            total = cl  # no Range support at all: full-file response
        if not total:
            raise RuntimeError("remote file size unknown (%r/%r/%r)" % (
                cr, linked, cl))
        return total, cr


def scan_remote_zip(url, max_pull=48 * 1024 * 1024):
    rr = RemoteRange(url, max_pull)
    total, cr = rr.probe_size()
    if total > 4 * 1024 * 1024 * 1024:
        return {"error": "file >= 4GiB (zip64) unsupported in remote mode",
                "remote_size": total}
    tail_len = min(total, 65536)
    tail_start = total - tail_len
    tail = rr._fetch(tail_start, total - 1, "EOCD tail")
    eocd_rel = tail.rfind(b"PK\x05\x06")
    if eocd_rel < 0:
        return {"error": "EOCD not found in tail; not a supported zip"}
    eocd = tail[eocd_rel:eocd_rel + 22]
    try:
        (_sig, _disk, _cddisk, _ndisk, _ntot, cd_size_e, cd_off_e) = \
            struct.unpack("<4sHHHHII", eocd[:20])
    except struct.error:
        return {"error": "EOCD parse failed (possible zip64 or corrupt)"}
    cd_end = cd_off_e + cd_size_e
    eocd_abs = tail_start + eocd_rel
    if cd_end > total:
        return {"error": "EOCD CD offsets exceed file size",
                "cd_end": cd_end, "remote_size": total}
    gap = eocd_abs - cd_end
    comment_len = struct.unpack("<H", eocd[20:22])[0] if len(eocd) >= 22 \
        else 0
    zip_comment = ""
    if comment_len:
        cs = eocd_rel + 22
        ce = cs + comment_len
        if ce <= len(tail):
            zip_comment = tail[cs:ce].decode("utf-8", "replace")
        else:
            zip_comment = "<%d bytes beyond fetched tail>" % comment_len
    cd = rr._fetch(cd_off_e, cd_off_e + cd_size_e - 1, "central directory")
    entries = []
    pos = 0
    while pos + 46 <= len(cd) and cd[pos:pos + 4] == b"PK\x01\x02":
        (sig, _vmade, _vneed, flags, meth, _mt, _md, crc, csize, usize,
         nlen, elen, clen, _disk, _iattr, _eattr, lho) = struct.unpack(
            "<IHHHHHHIIIHHHHHII", cd[pos:pos + 46])
        entries.append({
            "name": cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace"),
            "file_size": usize, "compress_size": csize,
            "compress_method": meth, "crc_hex": "0x%08x" % crc,
            "flag_bits": flags,
            "encrypted": bool(flags & 0x1),
            "data_descriptor": bool(flags & 0x8),
            "header_offset": lho})
        pos += 46 + nlen + elen + clen
    pickle_entries = [e for e in entries
                      if e["name"].lower().endswith((".pkl", ".pickle"))]
    notes = []
    if not pickle_entries:
        small = [e for e in entries if 0 < e["file_size"] < 8 * 1024 * 1024]
        pickle_entries = small[:2]
        if small:
            notes.append("no .pkl member; trying 2 smallest members")
    scans = []
    remote_anomalies = []
    for pe in pickle_entries:
        lho = pe["header_offset"]
        try:
            lfh = rr._fetch(lho, lho + 512, "LFH %s" % pe["name"])
        except Exception as e:
            notes.append("LFH fetch failed for %s: %s" % (pe["name"], e))
            continue
        if lfh[:4] != b"PK\x03\x04":
            notes.append("LFH magic missing at %d for %s"
                         % (lho, pe["name"]))
            continue
        (_, _, lflags, lmeth, _, _, _lcrc, lcsize, lusize, ln, eln) = \
            struct.unpack("<IHHHHHIIIHH", lfh[:30])
        data_start = lho + 30 + ln + eln
        csz = lcsize or pe["compress_size"]
        if lflags & 0x8:
            notes.append("member %s uses data descriptor" % pe["name"])
        try:
            data = rr._fetch(data_start, data_start + csz - 1,
                             "pkl bytes %s" % pe["name"])
        except Exception as e:
            notes.append("pkl fetch failed %s: %s" % (pe["name"], e))
            continue
        if lmeth == 0:
            pkl, base_abs = data, data_start
        else:
            try:
                pkl = zlib.decompress(data, -15)
                base_abs = None
            except Exception as e:
                notes.append("decompress failed for %s: %s" % (pe["name"],
                                                               e))
                continue
        pa = PickleAnalysis(pe["name"], pkl,
                            base_abs or 0).analyze()
        d = pa.to_dict()
        remote_anomalies.extend(_flags_from_pickle(pa, pe["name"]))
        if base_abs is None:
            d["note"] = "pickle was deflated; offsets are in decompressed " \
                        "space"
        scans.append(d)
    data_members = [e["name"] for e in entries
                    if not e["name"].lower().endswith((".pkl", ".pickle"))
                    and not e["name"].endswith("/")]
    return {
        "format": "torch_zip",
        "mode": "remote-range",
        "remote_url": url,
        "remote_size": total,
        "remote_content_range": cr,
        "remote_bytes_pulled": rr.pulled,
        "eocd_abs": eocd_abs,
        "cd_end": cd_end,
        "inter_section_gap_bytes": gap,
        "zip_comment": zip_comment,
        "entry_count": len(entries),
        "entries": entries,
        "data_member_count": len(data_members),
        "pickle_members": scans,
        "anomalies": remote_anomalies,
        "verify_note": "remote mode verifies EOCD adjacency (no local-file "
                       "CRC pass possible)",
        "notes": notes,
    }


# --------------------------------------------------------------------------
# generic text/source scans
# --------------------------------------------------------------------------

def scan_python_source(path, buf):
    text = buf.decode("utf-8", "replace")
    risks = []
    rules = [
        (r"\b(os\.system|os\.popen|subprocess\.[A-Za-z_]+)\(", "process_exec"),
        (r"\b(eval|exec|compile)\(\s", "code_exec"),
        (r"\b(socket|urllib\.request|urllib2|requests|httpx|ftplib|smtplib)"
         r"[\.\s(]", "network"),
        (r"\b(ctypes|cffi)\b", "native_bridge"),
        (r"\b(pickle\.loads?|torch\.load)\b", "deserialization"),
        (r"weights_only\s*=\s*False", "deserialization_unsafe"),
        (r"\b(base64|codecs|marshal|binascii)\b", "obfuscation_or_stage2"),
        (r"\b(shutil\.rmtree|os\.remove|os\.chmod)\b", "fs_mutate"),
        (r"\b(__import__|importlib\.import_module)\b", "dynamic_import"),
        (r"\b(keyring|getpass)\b", "credential_access"),
    ]
    for pat, label in rules:
        for m in re.finditer(pat, text):
            risks.append({
                "label": label,
                "line": text[:m.start()].count("\n") + 1,
                "match": m.group(0)[:80],
                "char_offset": m.start()})
    return risks


MAGIC_TARGETS = (
    (b"\x89PNG", "png"), (b"GIF8", "gif"), (b"RIFF", "riff"),
    (b"%PDF", "pdf"), (b"\xff\xd8\xff", "jpeg"),
)


def sniff(buf_head):
    if buf_head[:4] == b"PK\x03\x04":
        return "zip"
    if buf_head[:4] == b"PK\x01\x02" or buf_head[:4] == b"PK\x05\x06":
        return "zip"
    if buf_head[:4] == b"\x93NUMPY":
        return "npy"
    if buf_head[:1] == b"\x80":
        return "pickle"
    if buf_head[:1] in (b"\x0d", b"\x8a"):
        return "pickle"     # proto 0/1 legacy
    for magic, label in MAGIC_TARGETS:
        if buf_head[:len(magic)] == magic:
            return label
    if len(buf_head) >= 262 and buf_head[257:262] == b"ustar":
        return "tar"
    sample = buf_head[:2048].lstrip().lower()
    if b"import " in sample or b"<html" in sample or b"#!" in sample:
        return "text"
    return "unknown"


# --------------------------------------------------------------------------
# per-target orchestration
# --------------------------------------------------------------------------

def _slurp(path):
    with open(path, "rb") as fh:
        return fh.read()


def _slurp_head(path, n):
    with open(path, "rb") as fh:
        return fh.read(n)


def gather_flags(report, node, prefix=""):
    out = []
    if isinstance(node, dict):
        pk = node.get("anomalies")
        if isinstance(pk, list):
            for a in pk:
                if isinstance(a, dict):
                    a.setdefault("source", prefix)
                    out.append(a)
        for k, v in node.items():
            out.extend(gather_flags(v, prefix or k))
    elif isinstance(node, list):
        for v in node:
            out.extend(gather_flags(v, prefix))
    return out


ARCHIVE_SCAN_RISK_SEVERITY = {
    "process_exec": 1, "native_bridge": 1, "credential_access": 1,
    "deserialization_unsafe": 1, "code_exec": 1, "network": 1,
    "deserialization": 0, "obfuscation_or_stage2": 0, "fs_mutate": 1,
    "dynamic_import": 0,
}


def compute_verdict(report):
    reasons = []
    weaponized = [0]
    suspicious = [0]

    def walk(node):
        if isinstance(node, dict):
            if "globals_flagged" in node and isinstance(
                    node.get("globals_flagged"), list):
                for g in node["globals_flagged"]:
                    sev = g.get("severity", 0)
                    if sev >= 2:
                        weaponized[0] += 1
                        reasons.append(
                            "pickle device %s.%s [%s] @pickle+%s"
                            % (g.get("module"), g.get("name"),
                               g.get("category"), g.get("pos_in_pickle")))
                    elif sev == 1:
                        suspicious[0] += 1
                        reasons.append(
                            "pickle global %s.%s [%s] (suspicious)"
                            % (g.get("module"), g.get("name"),
                               g.get("category")))
            if "reduce_on_flagged" in node and isinstance(
                    node.get("reduce_on_flagged"), list):
                for cmd in node["reduce_on_flagged"]:
                    if cmd.get("called_severity", 0) >= 1:
                        suspicious[0] += 1
                        reasons.append(
                            "REDUCE invokes %s [%s]" %
                            (cmd.get("called"), cmd.get("called_category")))
            if node.get("allow_pickle_surface"):
                suspicious[0] += 1
                reasons.append("object-dtype (allow_pickle) surface: %s"
                               % node.get("label"))
            if "trailing_bytes_after_stop" in node and \
                    node.get("trailing_bytes_after_stop"):
                suspicious[0] += 1
                reasons.append("%d bytes after STOP (%s)" % (
                    node["trailing_bytes_after_stop"],
                    node.get("entry")))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(report.get("container"))
    walk(report.get("npy"))
    for a in (report.get("container") or {}).get("anomalies", []):
        sev = a.get("severity", 0)
        if sev >= 2:
            weaponized[0] += 1
            reasons.append("container: %s" % a.get("detail"))
        elif sev == 1:
            suspicious[0] += 1
            reasons.append("container: %s" % a.get("detail"))
    for f in (report.get("archive_scan") or {}).get(
            "embedded_markers_head", []):
        suspicious[0] += 1
        reasons.append("media marker: %s @%d"
                       % (f.get("kind"), f.get("offset_in_member", 0)))
    ascan = report.get("archive_scan") or {}
    if ascan.get("codec_tail_terminator_found") is False and \
            ascan.get("codec_tail_terminator_expected"):
        suspicious[0] += 1
        reasons.append("media tail terminator missing: possible appended "
                       "payload")
    scan_risks = (report.get("source_scan") or {}).get("risk_hits")
    source_ok = False
    if scan_risks:
        for h in scan_risks:
            sev = ARCHIVE_SCAN_RISK_SEVERITY.get(h.get("label"), 0)
            if sev >= 2:
                weaponized[0] += 1
                reasons.append("%s: %s (line %s)"
                               % (h.get("label"), h.get("match"),
                                  h.get("line")))
            elif sev == 1:
                suspicious[0] += 1
                reasons.append("%s: %s (line %s)"
                               % (h.get("label"), h.get("match"),
                                  h.get("line")))
        source_ok = True
    elif (report.get("sniffed_magic") == "text" and
          not scan_risks):
        source_ok = True
    if weaponized[0]:
        report["verdict"] = "WEAPONIZED"
    elif suspicious[0]:
        report["verdict"] = "SUSPICIOUS"
    elif (report.get("container") or {}).get("format") or \
            report.get("npy") or report.get("safetensors") or \
            (ascan.get("codec_tail_terminator_found") and
             report.get("sniffed_magic") in ("jpeg", "png", "gif", "riff",
                                             "pdf")) or source_ok:
        report["verdict"] = "CLEAN"
    else:
        report["verdict"] = "UNKNOWN"
    uniq = list(dict.fromkeys(reasons))
    report["verdict_reasons"] = uniq[:60]
    report["verdict_counts"] = {
        "weaponized_flags": weaponized[0],
        "suspicious_flags": suspicious[0],
        "distinct_reasons": len(uniq)}


def json_safe(o):
    """bytes/bytearray -> str|hex so every report is JSON-serializable."""
    if isinstance(o, (bytes, bytearray)):
        try:
            return o.decode("utf-8")
        except UnicodeDecodeError:
            return "0x" + bytes(o).hex()
    if isinstance(o, dict):
        return {json_safe(k): json_safe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [json_safe(v) for v in o]
    return o


def scan_one(target, is_url=False, out_dir=None, no_sha=False, no_crc=False,
             max_remote_pull=48 * 1024 * 1024):
    report = {
        "scanner_version": SCAN_VERSION,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime()),
        "artifact": target,
        "mode": "remote-range" if is_url else "local",
        "sha256": None,
        "verdict": "UNKNOWN",
        "verdict_reasons": [],
    }
    dis_dir = os.path.join(out_dir, "disasm") if out_dir else None
    if not is_url:
        if not os.path.isfile(target):
            report["error"] = "not a file"
            return report
        size = os.path.getsize(target)
        report["size"] = size
        if not no_sha:
            h = hashlib.sha256()
            with open(target, "rb") as fh:
                for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                    h.update(chunk)
            report["sha256"] = h.hexdigest()
        head = _slurp_head(target, 300)
        fmt = sniff(head)
        text_ext = target.lower().endswith(
            (".py", ".pyw", ".sh", ".json", ".txt", ".md", ".cfg", ".toml",
             ".yaml", ".yml", ".csv", ".tsv", ".log"))
        if fmt == "unknown" and text_ext:
            fmt = "text"
            report["text_by_extension"] = True
        report["sniffed_magic"] = fmt
        if fmt == "zip":
            try:
                zf = zipfile.ZipFile(target, "r", allowZip64=True)
                report["container"] = analyze_torch_zip(
                    zf, crc_check=not no_crc, dis_dir=dis_dir,
                    dis_prefix=os.path.basename(target))
                low = [e["name"].lower() for e in
                       report["container"]["entries"]]
                if low and all(n.endswith(".npy") for n in low
                               if not n.endswith("/")):
                    report["sniffed_magic"] = "npz"
            except Exception as e:
                report["error"] = "zip open failed: %s: %s" % (
                    type(e).__name__, e)
        elif fmt == "pickle":
            raw = _slurp(target)
            pa = PickleAnalysis(os.path.basename(target), raw, 0).analyze()
            d = pa.to_dict()
            d["legacy_note"] = "raw pickle at file head (legacy torch save)"
            if pa.stop_offset is not None:
                stop = pa.stop_offset
                d["trailing_blob_bytes"] = len(raw) - stop - 1
                d["trailing_blob_hex_base_offset"] = stop + 1
                d["trailing_blob_head_hexdump"] = hexdump(
                    raw[stop + 1:stop + 529], base=stop + 1, limit=512)
            report["container"] = d
        elif fmt == "npy":
            raw = _slurp(target)
            nbytes = len(raw)
            if nbytes <= 256 * 1024 * 1024:
                report["npy"] = parse_npy(raw, os.path.basename(target))
            else:
                report["npy"] = {"note": "file >256MB; header-only scan "
                                         "skipped in this run"}
        elif fmt == "tar":
            report["container"] = scan_tar(target, max_member_read=
                                           32 * 1024 * 1024)
        elif fmt in ("jpeg", "png", "gif", "riff", "pdf"):
            raw = _slurp(target)
            TERMINATOR = {"jpeg": b"\xff\xd9", "png": b"\xaeB`\x82",
                          "gif": b"\x3b", "pdf": b"%%EOF"}
            tc = TERMINATOR.get(fmt, b"")
            tail_ok = raw[-256:].find(tc) != -1
            COMMON_IMAGE_BYTES = {"pe_header", "pickle_proto2",
                                  "pickle_proto4", "pickle_proto3",
                                  "pickle_proto5"}
            mk = embedded_archive_markers(raw[:2 * 1024 * 1024], 0)
            kept_head = []
            for f in mk:
                if tail_ok and f["kind"] in COMMON_IMAGE_BYTES:
                    continue  # coincidental bytes inside compressed pixels
                kept_head.append(f)
            report["archive_scan"] = {
                "embedded_markers_head": kept_head,
                "embedded_markers_head_raw_count": len(mk),
                "codec_tail_terminator_expected": tc.rstrip(b"\x00") or tc,
                "codec_tail_terminator_found": tail_ok,
                "note": "in-body magic hits inside compressed pixel data "
                        "are almost always coincidental; only hits that "
                        "survive the tail-terminator check are surfaced",
            }
        elif fmt == "text":
            raw = _slurp_head(target, 32 * 1024 * 1024)
            if target.lower().endswith((".py", ".pyw", ".sh", ".ps1")):
                report["source_scan"] = {"risk_hits": scan_python_source(
                    target, raw)}
            else:
                report["source_scan"] = {"note": "plain text/JSON: not "
                                                 "flagged"}
        elif fmt == "safetensors":
            raw = _slurp(target)
            report["safetensors"] = parse_safetensors(raw,
                                                      os.path.basename(
                                                          target))
        else:
            raw = _slurp_head(target, 4 * 1024 * 1024)
            report["archive_scan"] = {
                "embedded_markers": embedded_archive_markers(raw, 0)}
    else:
        report["remote_url"] = target
        try:
            report["container"] = scan_remote_zip(
                target, max_pull=max_remote_pull)
        except Exception as e:
            report["error"] = "remote scan failed: %s: %s" % (
                type(e).__name__, e)
    compute_verdict(report)
    if out_dir is not None:
        os.makedirs(out_dir, exist_ok=True)
        if is_url:
            stem = _safe_name(re.sub(r"^https?://", "", target).replace(
                "/", "__"))[:200]
        else:
            stem = _safe_name(os.path.basename(target))[:120]
        rp = os.path.join(out_dir, stem + ".json")
        safe = json_safe(report)
        with open(rp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(safe, indent=2))
        report["report_file"] = rp
    return report


def main():
    ap = argparse.ArgumentParser(
        description="Passive ML-checkpoint/label-bank abuse scanner "
                    "(read-only; never deserializes untrusted bytes).")
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--out-dir", default="scan_reports")
    ap.add_argument("--url", action="store_true",
                    help="targets are URLs; range-based pickle-only scan")
    ap.add_argument("--no-sha", action="store_true")
    ap.add_argument("--no-crc", action="store_true")
    ap.add_argument("--max-remote-pull", type=int, default=48,
                    help="MB cap on remote bytes pulled (default 48)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "disasm"), exist_ok=True)
    rows = []
    for t in args.targets:
        if not args.quiet:
            print("[scan] %s %s" % ("URL" if args.url else "file", t),
                  file=sys.stderr)
        r = scan_one(t, is_url=args.url, out_dir=out_dir,
                     no_sha=args.no_sha, no_crc=args.no_crc,
                     max_remote_pull=args.max_remote_pull * 1024 * 1024)
        if not args.quiet:
            print("[done] %s verdict=%s" % (os.path.basename(t),
                                            r.get("verdict")),
                  file=sys.stderr)
        rows.append(r)
    summary = {
        "scanner_version": SCAN_VERSION,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts_scanned": len(rows),
        "rows": [
            {"artifact": r.get("artifact"), "verdict": r.get("verdict"),
             "sha256": r.get("sha256"),
             "format": ((r.get("container") or {}).get("format")),
             "weapons": (r.get("verdict_counts") or
                         {}).get("weaponized_flags", 0),
             "suspects": (r.get("verdict_counts") or
                          {}).get("suspicious_flags", 0),
             "reasons": r.get("verdict_reasons", [])[:12]}
            for r in rows],
    }
    sp = os.path.join(out_dir, "summary.json")
    with open(sp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(json_safe(summary), indent=2))
    if not args.quiet:
        print(json.dumps(json_safe(summary), indent=2))


if __name__ == "__main__":
    main()
