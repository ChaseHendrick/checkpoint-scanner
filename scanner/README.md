# checkpoint_scanner

Passive, **read-bytes-only** abuse-indicator scanner for ML checkpoints,
label banks, and model files — built for the Vesuvius Challenge artifact
ecosystem but usable on any `.pth`/`.pt`/`.ckpt`/`.npz`/`.npy`/`.tar`
checkpoint set.

## Safety model

The scanner **never executes, imports, `torch.load()`s, `pickle.load()`s,
or `eval()`s any scanned artifact.** Every check is byte-level parsing:

- zip/tar container metadata is parsed with `zipfile`/`tarfile` **without
  reading member contents for execution**,
- embedded pickle byte streams are walked with
  `pickletools.genops` — a textual opcode walker with no code-execution
  path,
- CRC32 / SHA-256 are verified by reading raw bytes only.

Standard library only, Python >= 3.9. Run it from an isolated,
low-privilege account and point it only at untrusted files.

## Usage

```bash
# Local files (full scan: hash + CRC + disassembly)
python3 scanner.py DIR/reader-v3.pth DIR/other.pth --out-dir scan_reports

# Remote URL (HTTP Range mode: pickle-header only, ~205 KB pulled for a
# 138 MB checkpoint). NEVER writes model bytes to disk.
python3 scanner.py https://host/repo/file.pth --url --out-dir remote_reports

# Options
--out-dir DIR           report destination (default ./scan_reports)
--url                   targets are URLs; range-based, pickle-only scan
--no-sha                skip whole-file SHA-256 (faster on huge files)
--no-crc                skip per-member CRC32 verification
--max-remote-pull N     MB cap on remote bytes pulled per artifact (default 48)
--quiet                 suppress per-file stderr progress
```

## What gets inspected (per format)

| Format | Inspection |
|---|---|
| torch zip (`.pth/.pt/.ckpt`) | central directory, member names/sizes/CRCs, embedded `data.pkl` opcode walk |
| legacy raw pickle | whole-file opcode walk |
| `.npy` / `.npz` | header parse, `allow_pickle` (object-dtype) detection, embedded object-pickle globals |
| `.tar` label banks | member headers, `.zarray`/`object_codec` flags, nested archive markers |
| safetensors | JSON header parse |
| media/text | polyglot markers (ELF/PE/zip signatures appended to images/text), embedded URLs |
| Python source | AST scan for eval/exec/pickle.load/socket/subprocess/URLs |

## Checks

1. **Pickle opcode walk** — `GLOBAL`/`STACK_GLOBAL`/`INST`/`OBJ`
   resolution against an allowlist (`torch.*`, `numpy.*`, declared
   project classes); code-exec / network / process-spawn / native-bridge
   / stage-2 obfuscation / dynamic-import gadgets; `REDUCE` on flagged
   callables; opcodes after `STOP`; malformed or truncated streams.
2. **String stashing** — base64-ish blobs, hex blobs, non-ASCII bytes,
   URLs inside the pickle.
3. **Container anomalies** — encrypted entries, duplicate member names,
   nested archive markers inside members, inter-section gaps, size
   mismatches, CRC mismatches, odd-sized data members.
4. **`.npz`/`.npy` object dtype** — `allow_pickle` surface detection plus
   globals of the embedded object pickle when present.
5. **Integrity** — whole-file SHA-256 (local mode), per-member CRC32
   (declared vs computed). Remote-range mode retrieves only small ranges
   (EOCD / central directory / pickle members) over HTTP.

## Verdict scale

| Verdict | Meaning |
|---|---|
| **CLEAN** | only allowlisted globals; no structural anomalies |
| **SUSPICIOUS** | gadget-adjacent but benign-looking content (unusual modules reached via `REDUCE`, object-dtype labels, structural flags) |
| **WEAPONIZED** | an execution-capable gadget present (`eval`/`exec`/`os.system`/`subprocess`/`socket`/`ctypes`/stage-2 pickle/…) |
| **UNKNOWN** | artifact could not be parsed reliably |

## Output

- `<out-dir>/<basename>.json` — one report per artifact. Top-level keys:
  `scanner_version`, `scanned_at`, `artifact`, `mode`
  (`local` / `remote-range`), `sha256`, `size`, `sniffed_magic`,
  `verdict`, `verdict_reasons`, `container` (members, count, format,
  `anomalies`), `verdict_counts` (`weaponized_flags`,
  `suspicious_flags`, `distinct_reasons`).
- `<out-dir>/disasm/<prefix>__<member>.dis` — full
  `pickletools.dis(genops)` text dump per scanned pickle member. The
  prefix is the artifact basename, so two artifacts that both embed a
  member named `data.pkl` never collide.
- `<out-dir>/summary.json` — one-row-per-artifact roll-up.

In v1.0.0, per-remote JSON filenames derived from the URL basename, so
scanning both `seed42/step-075000.pth` and `seed43/step-075000.pth` under
the same `--out-dir` overwrote one per-URL JSON — the `summary.json`
roll-up remained complete (all rows). Since **v1.0.1** the remote-mode
filename is the whole URL path (`dl.ash2txt.org__community-uploads__...
__checkpoint_final.pth.json`), so reports never collide. Historical
per-file evidence from the project's own v1.0.0 runs is kept in
per-group dirs (`scan_reports/remote/seed42/`,
`scan_reports/remote/seed43/`, and one dir per ash2txt dataset under
`scan_reports/remote_ash2txt/DatasetNNN/`).

Note: remote-range mode walks the full embedded `data.pkl` and flags
string stashing the same way local mode does (string-flag anomalies are
promoted into `container.anomalies` since scanner v1.0.0). Expected byte
volume is ~205 KB per 138 MB checkpoint (EOCD tail + central directory +
local-file header + the pickle member itself); the cap is
`--max-remote-pull` MB. The scanner does not verify member CRCs in
remote mode (no full-file access); integrity is instead established at
the file level by comparing the host-published LFS/blob digest with a
locally computed SHA-256 after download.

## Changelog

- **1.0.1** — remote-mode reports are collision-free (URL-path-derived
  filenames); scanner version string bumped; remote anomalies promoted
  (`["anomalies"]` in the container) instead of only in local mode.
- **1.0.0** — initial release. Remote-mode filenames collided on shared
  basenames; string flags were recorded per-member but not promoted into
  the top-level verdict in remote mode.

## Known benign patterns in the Vesuvius corpus

- `_codecs.encode` with latin-1 — legacy torch storage deserializer for
  tensor bytes; appears in every nnUNet-v2 checkpoint (all
  `DatasetNNN_*` models under dl.ash2txt.org community uploads).
`codecs.encode(bytes_str, 'latin1')` merely round-trips tensor storage
bytes through a str; the REDUCE on it is not code-execution.
- 64-hex strings in `ink_9um` checkpoints (`hex_blob`, at pickle offsets
  113,785 and 119,455/119,620) — the frozen value of the
  `fixed_scroll_prior_manifest_sha256` state key (and its duplicate
  inside the `fixed_scroll_prior` dict), i.e. a trainer-built
  scroll-prior data-manifest hash, scrubbed of its local path at
  release (`/path/removed-for-release`). Same value in every checkpoint
  of a given seed run; not a payload.
- torch tensor storage bytes under latin-1 string encoding that show up
  as "non_ascii_binary" string flags — tensor payload, not stashed text.

## Provenance of this scan set

Scripts: `../../checkpoint_scan_artifacts/scripts/jobA_hf.sh`
(domenicor046 + scrollprize Hugging Face repos) and
`../../checkpoint_scan_artifacts/scripts/jobB_hecate_ash2txt.sh`
(hecate + dl.ash2txt.org bruniss community uploads). Reports:
`../../checkpoint_scan_artifacts/scan_reports/` (local) and
`.../scan_reports/remote/` (range mode).
