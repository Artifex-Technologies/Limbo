# Sample runs: analysing one hostile file in a sealed guest

For Heimdall's quarantine (Heimdall's docs/IMMUNITY.md): a file ClamAV does not know is taken apart inside a throwaway guest, never on
the host, so a parser bug in the analysis tools (radare2, Ghidra, binutils) exploited by a crafted file stays inside that guest.

## How

- Root only: the admin socket (`POST /v1/sample-runs`, then `GET /v1/runs/{id}`), or `sudo limbo analyze FILE [COMMAND]`.
- The file is put in Limbo's inbox (`/var/lib/limbo/inbox`, root-only) and named there (a plain name; links are refused). Limbo
  reads it (at most 64 MiB), sends it into the guest on the ssh connection's input and stores it read-only as `~/sample/sample`. It
  is never made executable. The command runs from that folder with `LIMBO_SAMPLE_DIR` set to it.
- Only a **sealed** profile takes samples: `allow_sample: true`, network `none` or `sinkhole` (no route out either way), no sudo,
  no shared folder (`exchange_dir`), no host devices. Checked at every start. Example: `examples/malware-analysis.json` (the
  decompile image: radare2, Ghidra, YARA-X's `yr`), in mode `sinkhole` since 2026-11-18: a call-home from the sample, or from an analysis
  tool a crafted file has taken over, lands in the sinkhole's log (docs/SINKHOLE.md) and in the run's result, and `limbo analyze`
  prints it after the output. Running the sample itself is in scope since 2026-11-18 (`examples/app-vetting.json`).
- The sample's SHA-256 and size are in the audit log (`run.start`), like a bundle's.
- The default command is the image's `limbo-decompile triage` and `functions`: file type, hashes, imports, sections, strings, YARA
  matches (YARA-X's `yr` since 2026-11-18; the image installs it from Labyrinth's package repository, Sarina's
  `packaging/limbo/decompile/README.md`), and the function list. Output is capped at the profile's limit and is untrusted (it
  comes from a hostile file).
- Suggested ATT&CK techniques: names in the output that are typical of a technique (imports such as `CreateRemoteThread`
  or `ptrace`, a `CurrentVersion\Run` key; the table is `rust/limbo/src/attackhints.rs`) give a line each after the
  output of `limbo analyze` ("suggested: T1055 Process Injection (seen: CreateRemoteThread)"), and their IDs go into the
  run's `run.end` event (`suggested`), which `limbo report` shows. A name in the output says the file mentions it, not that
  it uses it, and a hostile file can plant names: these are leads for a person, not findings. Names nearly every Windows
  program imports (`IsDebuggerPresent`, `GetProcAddress`) are left out of the table.

Why not the decompile profile's shared folder: a virtiofs share is writable by the guest into a host directory and has not been
exercised (ARCHITECTURE.md, known weaknesses). A sample run needs no share at all.

## Containment

While Heimdall's lock (`/etc/heimdall/contained`) exists, runs on the agent socket (Sarina's agents and validation runs) are refused
with the code `contained`, and `POST /v1/agent-runs/stop` (admin) ends the ones running: Heimdall calls it when it contains Sarina.
Sample runs for Heimdall go on.
