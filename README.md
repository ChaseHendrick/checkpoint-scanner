# Submission package — Vesuvius security report (October 2026 Progress Prize)

**The submission is one file: `VESUVIUS-SECURITY-REPORT.pdf`.** Everything the reviewers need sits inside it — the executive brief, every finding card, the prize-form answers, the digest pin set, and the audit transcripts as appendices. No Google Drive, no external hosting.

## Where it goes (order matters)

1. **File the private GitHub security advisory on `ScrollPrize/villa` first.** Attach this PDF plus the labeled evidence pack — `VESUVIUS-AUDIT-EVIDENCE-PACK.zip` — theirs for anyone who wants to see payloads: every proof-of-concept and effect artifact, the finding→artifact map, `README-FIRST.txt`, and `MANIFEST.sha256` inside for verifying the contents.

## Files

- `VESUVIUS-SECURITY-REPORT.pdf` — the submission report (the one file reviewers read; the advisory attachment)
- `VESUVIUS-AUDIT-EVIDENCE-PACK.zip` — the payloads, clearly labeled, attached to the advisory or handed over on request
- `MASTER-REPORT.md` — same content as the PDF, machine-readable source it is built from
- `04-PIN-SHA256.txt` — standalone digest pins (`shasum -a 256 -c 04-PIN-SHA256.txt`); also embedded as section 4 of the report

Embargo state: pre-patch. Payloads live only in the evidence pack (this folder's zip).
