# states.md — index

This directory models three protocols of the `file-storage` gear as three
independent TLA+ specs, each with its own step-by-step protocol write-up:

- **`states-upload.md`** — create → sidecar PUT → finalize → bind → delete →
  sweep → read (single-part upload, no multipart). Step prefixes: **U**
  (upload: create/PUT/finalize), **B** (bind), **D** (delete), **S** (sweep),
  **R** (read). Models: `FileStorageUpload.tla`.
- **`states-multipart.md`** — initiate → part upload → report_part →
  complete → abort → sweep, plus a two-session auto-bind race. Step
  prefixes: **M** (initiate/part/report/complete/abort/auto-bind), **MS**
  (sweep touching multipart sessions). Models: `FileStorageMultipart.tla`
  (one session, the full per-part machinery) and
  `FileStorageMultipartTwoSessions.tla` (two independent sessions racing to
  auto-bind the same file — a separate, minimal model, see its own header).
- **`states-migration.md`** — `migrate_backend` (one version, backend
  relocation): lease acquire → transfer/verify → CAS → cleanup, racing a
  concurrent delete, a concurrent reader, lease expiry, timeout and client
  cancellation. Step prefix: **G** (migrator actions), **G.D** (deleter),
  **G.R** (reader), **G.X** (external actor, #5013). Model:
  `FileStorageMigration.tla`.

Each `states-*.md` names real code paths (functions, transactions, backend
calls) next to the step id its model action implements, and calls out every
place the model deliberately diverges from (or narrows) the real code,
inline. See `README.md` for what is modelled/not modelled at a glance, run
instructions, results, and the findings.

As of 2026-10-02, the code has fixes for five of this directory's findings
(G.12/G.14, F1, F3, M7, M8's deep shape); each `states-*.md` has its own
"Fix status" note near the top, and the top-level `README.md` has the full
picture (fixed vs. still-open, the new per-fix boolean `CONSTANT`s, how to
reproduce the original bugs via those constants, and the current results
table).
