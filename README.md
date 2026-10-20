# Submission Package — Vesuvius security report (October 2026)

**The submission is one file: `VESUVIUS-SECURITY-REPORT.pdf`.** Everything the reviewers need sits inside it — the executive brief, every finding card, the prize-form answers, the digest pin set, and the audit transcripts as appendices. No Google Drive, no external hosting.

## Files

- `VESUVIUS-SECURITY-REPORT.pdf` — the submission report (the one file reviewers read; the advisory attachment)
- `VESUVIUS-AUDIT-EVIDENCE-PACK.zip` — the payloads, clearly labeled, attached to the advisory or handed over on request
- `MASTER-REPORT.md` — same content as the PDF, machine-readable source it is built from
- `04-PIN-SHA256.txt` — standalone digest pins (`shasum -a 256 -c 04-PIN-SHA256.txt`); also embedded as section 4 of the report

Embargo state: pre-patch. Payloads live only in the evidence pack (this folder's zip).
