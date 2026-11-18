# Leak Rehearsal

**Practice catching synthetic key exposure before trusting a log-redaction change.**

Generate a fixed, explicitly fake key in configuration dumps, authorization logs, exception text and exported/encoded forms. Feed those fixtures through your local redactor, capture its outputs, and check both **canary removal and preservation of benign controls**.

This is a defensive rehearsal, not a general credential scanner or production redaction library. It never reads environment variables, discovers files recursively, contacts credential issuers, validates real keys or sends captured data anywhere.

The sections below describe the original redaction mode. For the separate fixed SQLite credential-recovery exercise, see [the hands-on recovery task](docs/RECOVERY.md); its input, execution and exit-code rules differ.

## Run the complete redaction demo

Python 3.11+, no runtime dependencies. From this repository:

```sh
python -m leak_rehearsal generate --out rehearsal-fixtures
python -m leak_rehearsal audit rehearsal-fixtures/capture-catalogue.json --out passing-report
python -m leak_rehearsal verify passing-report rehearsal-fixtures/capture-catalogue.json
python -m unittest discover -s tests -v
```

Always use fresh output directories. Optional installation: `python -m pip install .`, then `leak-rehearsal` replaces `python -m leak_rehearsal`. Setuptools is needed to build the package; no package-registry release is implied.

The generated directory contains the corpus plus four **illustrative local policies**, not competing products:

| Capture | Demonstration | Cases with a detected canary form | Overall result |
|---|---|---:|---|
| `capture-none.json` | No redaction | 11 | failed |
| `capture-literal.json` | Replace only the plain key after joining chunks | 7 | failed |
| `capture-chunkwise.json` | Replace the plain key independently within each chunk | 8 | failed |
| `capture-catalogue.json` | Join chunks, then replace every supported full form | 0 | corpus_pass |

For example:

```sh
python -m leak_rehearsal audit rehearsal-fixtures/capture-chunkwise.json --out chunk-boundary-report
```

This exits **3**. Inspect `review.md`: the key split between two writes survives the naive chunk-local replacement and is detected after reassembly. This is an intentionally constructed regression demonstration, **not** a finding about an external product.

The catalogue demonstration knows the exact public canary and forms. Passing it is not evidence of a general-purpose redactor's quality.

## Exercise your own authorized local pipeline

1. Generate the fixtures. Use only the supplied public fake value, never a real token.
2. For every case in `corpus.json`, process its `chunks` using your test adapter. If evaluating streaming behavior, preserve the specified chunk boundaries when feeding the redactor, then collect the resulting text. The corpus's `preserve` values are explicit benign controls that should remain.
3. Write one capture JSON with `schema`, `corpus_version` and `outputs`. Each output has exactly `case` and `text`:

```json
{
  "schema": 1,
  "corpus_version": "fixed-synthetic-v1",
  "outputs": [{"case": "config_dump", "text": "your collected output here"}]
}
```

This fragment illustrates the shape only. All **13** case IDs must appear once for a pass. Unknown or duplicate IDs are invalid; missing cases are reported, never silently treated as clean.

4. Run `python -m leak_rehearsal audit YOUR_CAPTURE.json --out NEW_REPORT_DIRECTORY`.
5. Retain your capture locally. Recompute later with `python -m leak_rehearsal verify REPORT_DIRECTORY YOUR_CAPTURE.json`.

The original redaction CLI **does not execute your adapter or arbitrary supplied commands**. The optional recovery CLI runs only its packaged fixed Python worker, never supplied commands. You control and authorize the local test pipeline separately. No real application or production log collection occurs automatically.

### Actual Python logging example

An included adapter runs the corpus through a standalone Python `logging.Logger` with a synthetic-only filter and an in-memory `StreamHandler`. It never changes root logging configuration or reads application logs:

```sh
python -m examples.logging_adapter logging-capture
python -m leak_rehearsal audit logging-capture/capture.json --out logging-report
python -m leak_rehearsal verify logging-report logging-capture/capture.json
```

Run this example from the source checkout. It joins fixture chunks before logging; **it does not demonstrate streaming redaction correctness**. It demonstrates wiring a real logging filter to the capture contract. Replace the adapter in your own authorized tests, not the auditor. The example filter is not offered as a production secret filter.

## What the audit checks

The fixed version has 11 positive cases and 2 benign controls:

- Plain values in config dumps, Bearer-style headers and exception messages.
- Percent-encoded URL text with upper/lower percent hex digits.
- Standard Base64, padded and unpadded forms.
- Lower/upper hexadecimal text.
- A full lowercase `\uXXXX` escape sequence for every ASCII canary character.
- A plain value split across two chunks and reassembled in the captured result.
- A public near-match string and an ordinary status/retry payload that must survive.

Every supported full form is searched in **every captured case**, not only its expected case. Detection is exact substring matching of the fixed representations after parsing the capture JSON. It does not recursively decode arbitrary data. Overlapping or identical representations can produce multiple form names for the same occurrence; form names are not counts of independent leaks.

Each case also needs its exact `operation=complete` text and unique public trace marker. Control cases add another exact benign value. Empty text, discarded log lines and broad prefix redaction therefore cannot obtain a clean result merely by removing the canary. `missing_control_indices` refer to the case's `preserve` array.

These checks are intentionally limited. An adapter can fabricate the control markers or bypass the real application and still pass. They do not authenticate pipeline execution or measure overall usefulness of redacted logs.

### Status and exit codes

- `corpus_pass`: all 13 cases are present, no known full form was found, and every listed benign control remains.
- `failed`: a captured case contains a known form or loses a control. Missing cases remain visible alongside failures.
- `incomplete`: no captured case failed, but one or more cases are missing. An empty capture is incomplete.

`generate` exits **0** on completion. `audit` and `verify` exit **0 only for corpus_pass**, **3 for failed or incomplete**, and **2 for invalid input, inconsistent evidence, bounds or filesystem errors**. A failed report can recompute consistently and still exits 3. Verification is not a way to turn a failing rehearsal green.

## Reports and privacy

Reports contain only fixed case/stage/form names, control indices, counts, status, corpus hash and capture hash. **They do not copy captured text, filenames, paths, snippets or matched values.** `review.md` is a compact table; `report.json` is machine readable.

To verify, the original capture is supplied separately and compared through deterministic recomputation. There is no copied capture in a report directory. The hash binds exact bytes, including whitespace, but is not a signature or proof of source. Coordinated changes to capture and report are outside this integrity check.

Captures are written by you and may accidentally contain sensitive material. Use synthetic-only isolated tests; do not upload actual credentials or production logs to this project. The fixed canary is public and intentionally invalid as any real provider credential. No telemetry, environment inspection, network access or credential verification exists in this tool. No private vulnerability-reporting address is designated; keep secrets out of public issues.

## Boundaries and non-guarantees

This cannot find unknown real secrets, arbitrary truncated fragments, transformed values outside the listed forms, encrypted/compressed content, screenshots, hidden Unicode separators, double/nested encodings, or content never captured. It does not inspect a process's memory, live streams, files outside the explicit capture, HTTP traffic or third-party systems. A pass is **not** a confidentiality guarantee, provider-specific secret-scanner benchmark, penetration test or approval to publish logs.

Inputs must be ordinary non-symlink UTF-8 files no larger than 1 MiB. The capture has at most 13 records, each text at most 16,384 Unicode characters. JSON duplicate keys, invalid Unicode, excessive nesting, floating-point metadata and unknown fields are rejected. Leaf symlinks and special files are rejected; hostile parent-directory changes are not an OS sandbox guarantee. Errors avoid echoing supplied contents.

Generated files are serialized and bounded before creating the destination; the per-file output cap is 2 MiB. Existing output directories are not overwritten. An I/O failure may leave a partial directory; treat it as incomplete. Report verification rejects extra/missing files and any inconsistent bytes.

## Existing tools and honest scope

- [Gitleaks](https://github.com/gitleaks/gitleaks) is a broader secret-detection tool with custom rules and repository workflows. This rehearsal does not replace it or test its provider-rule coverage.
- [redact-transcripts](https://github.com/crossvault/redact-transcripts) provides transcript redaction, a public synthetic corpus and streaming behavior. This project makes no claim that synthetic tests or chunk handling are novel.
- [redact-secret-benchmarks](https://github.com/redact-secret/redact-secret-benchmarks) covers broader synthetic detection/redaction comparisons and adapter boundaries.

Only primary documentation was reviewed; these tools were **not executed** for a comparison. The four built-in demonstration policies are deliberately simple teaching fixtures, not stand-ins for those competitors. There is no head-to-head superiority claim. The concrete deliverable is a bounded synthetic exercise/capture/audit/recompute loop with benign-control and missing-case checks and a real Python logging example.

## Validation

31 public synthetic tests execute on Linux/Python 3.12: known representations in every case, every two-part split of the fixed plain canary, control preservation, empty/missing capture handling, explicitly unsupported secret/partial cases, real Python logging capture, capture and report byte tampering, strict input bounds, non-disclosing reports/errors, special-file rejection and CLI exit codes.

No Windows/macOS, hosted CI, production redactor or real application deployment has been tested. FIFO/symlink tests can skip where unsupported; skips are not passes. No browser UI is included or claimed tested.

MIT license. Original code and fixture content by walker512. No real keys, personal logs, upstream competitor implementation or user-private data are included.

## Optional local recovery exercise (0.2)

Practice actual persistent synthetic-token revocation, read-only replacement scopes and consumer switching with `python -m leak_rehearsal.recovery`. Start with [the hands-on recovery task](docs/RECOVERY.md). This is a fixed local SQLite exercise, not real-provider rotation, a production security service or an OS sandbox. Original redaction functionality and 31 tests remain unchanged.

The recovery increment adds 23 tests: **54 total passed, zero skips** on the tested Linux/Python 3.12 environment. An offline wheel installation also completed the two-scenario recovery demo and verification outside the checkout. See its documentation for the precise execution and evidence limitations.


### Recovery at the audit limit

The recovery exercise now reserves one final containment event after its 256
ordinary events, so filling the teaching journal does not alone prevent old-token
revocation. Repeated terminal revocations explicitly report use of the existing
event rather than pretending to create more audit records. Other commands still
refuse at capacity; this is not a successful recovery probe or production audit
solution. See [capacity semantics](docs/RECOVERY.md). The corrected local suite
has 67 tests passing, zero skips; no new GUI or cross-platform claim is made.

### Private, exclusive output directories

New `generate`, `audit` and recovery `demo` bundles reserve a fresh directory
with POSIX mode `0700` and create each output exclusively with mode `0600`
(subject to a more restrictive umask). Existing files, directories and dangling
or ordinary leaf symlinks are rejected without changing their contents or
permissions. Generated report bytes and verification of old bundles remain
unchanged. Existing reports are **not** retroactively made private.

Audit output does not contain captured text, but counts, statuses and hashes
can still disclose information. Review before sharing. On Windows these mode
arguments are not a verified owner-only ACL guarantee; use an appropriately
restricted destination. No Windows/macOS or new hosted CI validation is claimed.
Parent directories must be trusted and stable: this is not protection against
another process running as you or malicious concurrent parent replacement.
Publication is not atomic. A write failure can leave a private, incomplete
directory; it is not automatically deleted or overwritten, and retry requires
a new destination. Verify before use. No source capture or historical output
permissions are changed.

The privacy regression suite exercises a real subprocess with umask 022,
exclusive concurrent reservations, existing files/directories, leaf symlinks,
member substitution, failure preservation and pre-publication bounds. POSIX
permission tests and unsupported symlink tests skip explicitly on platforms
that cannot exercise them; a skip is not a pass.

### Initialization connection lifetime

The recovery exercise explicitly closes its SQLite initialization connection after
transaction commit or rollback, including interruption. This does not change
existing exercise data or delete an incomplete database on failure. The transaction
context alone did not close the connection in earlier versions.

This fix was tested on Linux/Python 3.12 with 79 tests, including repeated real
SQLite success, statement failure and interruption with garbage collection disabled
and connection references retained. Failed connection creation remains a controlled
error with the exclusively created partial file preserved. These checks are not a
new Windows/macOS, provider or production-service validation.
