# Recover the synthetic report application

This optional 0.2 mode is a runnable local exercise, not a production authorization implementation. Only fixed public fake credentials exist. No token, URL, environment-secret, provider or supplied-script input is accepted. No socket is listened on or connected. A fresh fixed Python worker handles each action against the same SQLite database. Process separation is not OS privilege separation.

## Hands-on task

Use Python 3.11+ and a fresh database path:

```
python -m leak_rehearsal.recovery init --db exercise.sqlite3
python -m leak_rehearsal.recovery act --db exercise.sqlite3 old-read
python -m leak_rehearsal.recovery act --db exercise.sqlite3 issue
python -m leak_rehearsal.recovery act --db exercise.sqlite3 revoke-old
python -m leak_rehearsal.recovery act --db exercise.sqlite3 app-read
python -m leak_rehearsal.recovery act --db exercise.sqlite3 switch-replacement
python -m leak_rehearsal.recovery probe --db exercise.sqlite3
```

Observe the application request fail after revocation and before switching. Issuing a replacement does not update the consumer. The replacement can read the actual synthetic report, but write/delete requests are denied by its fixed read-only scope. The final probe requires an application read, old-token refusal, replacement read, and both scope refusals. It is a fixed teaching probe, not a production health check. Every request records a persistent event. Reads return a digest of actual report data, not credential text.

`switch-old` changes the consumer but cannot restore the revoked credential. `revoke-old` and `issue` are idempotent and never re-enable or broaden credentials. There is no enable, arbitrary scope, arbitrary resource or SQL command. Initial old scope is deliberately overbroad. Probe never invokes old-token write/delete; it cannot delete the fixture. Failed scope checks leave the business row unchanged. There is no general mutating API example or claim to production authorization quality.

For both full sequences:

```
python -m leak_rehearsal.recovery demo --out new-evidence
python -m leak_rehearsal.recovery verify new-evidence
```

The demo actually runs 27 fresh client workers against two isolated temporary databases. It also executes the original catalogue redaction check. Redaction passes but an old-token request still succeeds: hiding logs does not revoke access. The contain-first sequence records an outage and recovery, then proves switching back cannot resurrect a revoked credential. The switch-first sequence demonstrates a different availability outcome, **not advice to delay emergency containment after exposure**. Actual compromise response depends on risk, issuer capabilities and consumers. See [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) for context, not certification of this code.

## Evidence and limitations

Receipt records every fixed action and result; report rescoring checks exact coverage, protocol and expected statuses. Missing/reordered results are errors; recorded unexpected outcomes fail. `verify` only rescores supplied records and compares report bytes. It does not contact a service, replay requests or authenticate history. Someone who edits all files consistently can fabricate evidence. Neither database markers nor hashes authenticate origin. Reports omit credential literals and user paths; SQLite stores fixed synthetic credential digests and public business data. Do not put real secrets or private data in these files.

Only this tool's self-created database should be used. The CLI checks fixed schema, fixed values, size (1 MiB), ordinary non-symlink leaf files, no sidecars, and at most 256 events. Schema validation is not a sandbox for malicious SQLite files. Same-user direct database edits can bypass all teaching rules; no resistant audit log is claimed. Trusted local parent directories are required; hostile path races are not solved. SQLite uses a one-second lock timeout and a two-second SQL progress budget. Each fixed worker has a five-second execution deadline and 16 KiB output budget, polled incrementally; startup, filesystem and cleanup can exceed these nominal limits. This is not a hard resource/memory/disk sandbox. Workers receive an empty explicit environment and no stdin, and execute only the packaged fixed Python entrypoint, not arbitrary supplied code.

A failed action returns a controlled error, never a success observation. A probe is multiple distinct transactions and can be partial if interrupted or its event budget is exhausted; do not treat it as atomic. An init I/O error can leave a partial file; no automatic deletion or replacement occurs. Demo output must not exist and writes bounded, pre-serialized files only after all requests finish; a write failure can leave incomplete evidence. Verify rejects extra/missing files. Interrupted demos do not create a completed report.

`init`/`act` exit 0 for a completed operation, including observed authorization refusal. `probe` exits 3 unless recovery-ready; `demo`/`verify` exit 3 for a scored mismatch. Invalid input, worker, filesystem or consistency errors exit 2. `leak-recovery` is the installed equivalent of `python -m leak_rehearsal.recovery`.

Only synthetic Linux/Python execution is tested. No actual provider, cloud account, real credential, real compromise, hosted service, Windows/macOS, UI or external security assessment is covered. This increment does not claim superiority to scanners or secret-management tools.

**Event cap is a teaching limitation:** after 256 requests the exercise refuses every further action, including revocation. Start a new exercise database. This is deliberately not a production credential manager and refusal to revoke at an audit-log cap is not recommended security practice. `act` exit 0 means the fixed action completed, not that authorization succeeded; inspect its `status`. Only `probe` asserts the recovery conditions.

## Validation of this increment

54 tests passed with zero skips on Linux/Python 3.12 (31 original unchanged plus 23 recovery tests). These exercise real fresh workers, persistence, outage/recovery, irreversible/idempotent actions, scope refusal with unchanged synthetic data, redaction versus revocation, receipt semantic tampering, complete coverage, report bytes, CLI exit codes, special files, sidecars, schema and size limits. An offline wheel was built without fetching packages, installed in a new virtual environment, then `leak-recovery demo` and `verify` ran outside the source checkout. Both scenarios matched through 27 real fixed-worker invocations. Installed recovery source bytes were compared with the tested source. No actual provider, real credential, network service or GUI was tested.
