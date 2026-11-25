# The Rust port of Limbo

I want as much of the ecosystem as possible in Rust, for lightness and smoothness while I game and run a local model.
`limbo serve` is Limbo's always-on part, so it goes first; Heimdall's port (its `docs/RUST_PORT.md`) is the model. The
Go daemon measured 18.8 MB RSS idle on my PC; the target was about 3-5 MB.

**Since 2026-11-15 Limbo is Rust only.** `limbo-rs`, installed as `/usr/bin/limbo`, is the daemon (`limbo serve`) and
every command of the CLI; the Go sources (about 26,300 lines), the Go hand-over in `main.rs` and the Go build in the
recipes are gone. The Go limbo is still the referee of every proof: the differential runs build it from the last commit
that had it ("The Go side"), and the fixtures in `testdata/parity` are what that commit's Go tests wrote. The CLI was
ported command by command from 2026-11-11 (the socket-client commands, then the manifest, file, guest, passthrough and
Wine commands), and `net watch` and `capture` last (2026-11-15, "What still reached Go").

## Status

| Step | What | State |
| --- | --- | --- |
| 1 | every package `serve` uses, in `rust/limbo`: events, quarantine, settings, manifest, virt (XML, subnets), policy, hostfw, provision, disk, image proofs, license, exchange, hostpolicy (the serve side), engine, runs, instances, flows (aggregator + NFLOG socket), the HTTP layer with Go's ServeMux rules, api, serve | **done** (2026-11-10) |
| 2 | the Go fixtures (`testdata/parity`), the properties, fuzz targets and Kani harnesses | **done**: see "Proof" |
| 3 | the differential run of both daemons on the same socket traffic (`rust/parity/daemon-differential.py`) | **done**: no difference |
| 4 | the real-guest scripts against the Rust daemon (`LIMBO_RS=... scripts/integration-*.sh`) | **done** (2026-11-11): quarantine 71/71, sarina 15/15, chain 32/32 with limbo-rs ("The owner's first run") |
| 5 | the rehearsal on a copy of this computer's real state (`--from-host`), then the switch | **done**: rehearsal no difference; my PC switched by hand (drop-in) on 2026-11-10, no restart since; the package ships it since 2026-11-11 ("Packaging") |
| 6 | the CLI commands, one by one | **done**: the five socket-client commands, then version, validate, plan, address, seed, report, analyze, image, doctor, setup, up, down, launch, export, screenshot, passthrough and wine (2026-11-11, `cli.json`, `cliclient.json`, `manifests.json`, `tz.json`, `wine.json` and the CLI differential run); `net watch` and `capture` (2026-11-15) |
| 7 | the Go code out of the repository and the recipes | **done** (2026-11-15): "What still reached Go", "The Go side" |

## What still reached Go (inventory of 2026-11-15, before the removal)

Until 86a479f, `main.rs` handed a command line to the Go build (`go_binary`: `$LIMBO_GO_BINARY`, `limbo-go` beside
limbo-rs, `/usr/lib/limbo/limbo-go`, `/usr/bin/limbo`) in these cases, and only these:

| Path to Go | Go code it ran | Now |
| --- | --- | --- |
| `limbo net watch [--seconds N]` | `cmd/limbo/net_cmd.go`; `internal/flows` (Listen on NFLOG group 7213, the Aggregator); `policy.NFLogGroup` | `cli/net.rs` on the daemon's `flows` module; CLI differential `net_cases` (real NFLOG packets in CI) |
| `limbo capture [--seconds N] MANIFEST OUT` | `cmd/limbo/main.go` `capture`; `internal/usbcap` (Find, the pcap writer, the MON_IOCX_GETX loop); `manifest` | `usbcap.rs`, `cli/capture.rs`; CLI differential `capture_cases` with `examples/usbmon_fake.rs` |
| any argument that is not UTF-8 (every command, `serve` included) | the whole CLI | refused, exit status 2 (`tests/dispatch.rs`); see "Differences" |
| `SUDO_USER`, `USER`, `PKEXEC_UID`, `SUDO_UID`, `SUDO_GID`, `HOME`, `LIMBO_STATE_DIR`, `TMPDIR` or `WAYLAND_DISPLAY` not UTF-8 | the whole CLI | refused, exit status 2 |
| `limbo wine` with any environment variable or the working folder not UTF-8 | `cmd/limbo/wine_cmd.go`, `internal/wine` | a variable wine reads or hands to the sandbox is refused, any other left out (it never reached the sandbox in Go either); a folder that is not UTF-8 is refused |

Every other Go package (api, deps, disk, engine, events, exchange, hostfw, hostpolicy, image, instances, launch,
license, manifest, policy, provision, quarantine, report, runner, runs, settings, virt, wine, and parity, the fixture
writer) ran on no user's machine any more: limbo-rs ran those commands itself, and the Go code was only the referee of
the fixtures and the differential runs. Lines at the pinned commit (code + tests): cmd/limbo 2,814 + 1,554, wine 2,143
+ 1,719, api 1,245 + 1,256, runs 1,064 + 1,070, instances 828, image 740 + 793, hostpolicy 722 + 1,113, virt 616 +
321, engine 609 + 837, flows 602 + 414, the rest under 450 each; 26,273 in all.

## The Go side (the referee, from a pinned commit)

The Go sources left the repository with the commit after **86a479fbc33cca7aaa6c9e4d943562b0825ad8ba**, the last one
that has them (and the first whose limbo-rs hands nothing to Go). `rust/parity/go-limbo.sh OUT` builds that commit's Go
limbo with `git archive` into a temporary folder, with today's `VERSION` put over the old one so both report the same
version; CI runs it (a full clone, `fetch-depth: 0`) before both differential runs, so every proof below stays
reproducible after the deletion. The fixtures in `testdata/parity` were written by that commit's Go tests and are kept
as data; a deliberate change to the Rust behaviour that the fixtures pin now means writing new expectations on purpose
(check the commit out elsewhere, change the Go side there, `LIMBO_PARITY_UPDATE=1 go test ./internal/... ./cmd/limbo
-run Parity`, copy the file), or a fixture of Rust's own. The Go unit tests that pinned something besides behaviour went
with it except `internal/deps`'s packaging test, carried over as `rust/limbo/tests/packaging.rs` (every package `limbo
setup` installs is in the PKGBUILD's optdepends, none in depends, and no Go build in the recipe).

## Python and shell in the repository (2026-11-15)

None of them ships or runs on a user's machine; each is a referee or a test, kept on purpose:

| File | Lines | What |
| --- | --- | --- |
| `rust/parity/cli-differential.py` | 2,051 | the CLI differential (referee) |
| `rust/parity/daemon-differential.py` | 827 | the daemon differential and the rehearsal on a copy of the real state (referee) |
| `scripts/fake_model.py` | 110 | the scripted model for the Sarina integration scripts (test) |
| `rust/parity/go-limbo.sh` | 22 | builds the Go referee from the pinned commit |
| `scripts/integration-*.sh`, `it-common.sh`, `limbo-bin.sh`, `rust-checks.sh` | 1,366 | the owner's real-guest tests (root, a hypervisor) |
| `rust/scripts/nicecargo.sh` | 4 | cargo at nice 15 |

The packaging's shell is the recipe format itself (`PKGBUILD`, `limbo.install`, run by makepkg and pacman), not a
program of ours. One shell file does ship: **`packaging/wine/wine`**, the 4-line shim installed as
`/usr/lib/limbo/bin/wine` (and Wine's other command names as links to it), which only `exec`s `/usr/bin/limbo wine
--shim -- ...` by the name it was called with. It is left as shell for now: porting it means a second Rust binary (or a
multi-call limbo) for one `exec`, and the work goes first to what decides behaviour. It is next in line if the rule is
read strictly.

## Layout

```
rust/
  Cargo.toml, Cargo.lock      workspace; exact versions (sha2, rustix, libc; proptest and serde_json for tests)
  limbo/src/                  one module per Go package, named in its first line
    gojson.rs, gotext/, gotime.rs   Go's behaviour where Rust's differs (below); from Heimdall's port, extended
    http.rs                   HTTP/1.1 on a unix socket, one request per connection, Go's ServeMux matching
    api.rs                    the route tables (one function), handlers, the Kani harnesses on the tables
    serve.rs                  startup in Go's order, one poll(2) loop, a thread per connection and per run
    main.rs                   `serve`, `rs-version`, else the CLI (cli/); a command line that is not UTF-8 is refused
  limbo/tests/                parity_* (the Go fixtures), properties.rs (exhaustive claims, proptest, fuzz bodies),
                              dispatch.rs (command lines and variables that are not UTF-8), packaging.rs
  examples/usbmon_fake.rs     the usbmon stand-in for the capture differential (seccomp user notification; not shipped)
  fuzz/                       cargo-fuzz targets (nightly): http_request, json, manifest, nflog
  parity/daemon-differential.py   both daemons, the same traffic, compared
  parity/cli-differential.py      both CLIs, the same arguments, files and answers, compared
  parity/go-limbo.sh              the Go referee, built from the pinned commit
  scripts/nicecargo.sh        cargo at nice 15
testdata/parity/              the fixtures the Go tests of the pinned commit wrote (internal/parity, parity_test.go there)
scripts/limbo-bin.sh          the binary the integration scripts test: $LIMBO_BIN, else rust/target/release/limbo-rs
```

Threads, no async. The release binary is 1.5 MB and links only libc and libgcc_s.

## Behaving exactly like the Go daemon

The port has to answer, log and run the same, byte for byte, or the comparison means nothing. Where Rust's standard
behaviour differs from Go's, the port carries Go's:

- **JSON decoding** (`gojson`): Go's exact error texts reach callers (an agent-socket refusal quotes the decoder; a
  profile refusal too), so the reader gives the scanner's syntax errors (`invalid character '}' looking for beginning
  of object key string`), the stream reader's `unexpected EOF` and EOF, type errors with Go's struct and field path
  (`json: cannot unmarshal string into Go struct field Manifest.cpus of type int`; anonymous request structs have an
  empty name, map elements are named by their key), `DisallowUnknownFields`, the first error in document order winning.
  Keys match fields without regard to case, the last duplicate wins, lone surrogates and stray bytes read as U+FFFD.
  Nil and empty slices are kept apart (`null` against `[]` in saved manifests).
- **JSON writing**: Go's escaping (`<`, `>`, `&`, U+2028, U+2029), struct field order, sorted map keys, `omitempty`,
  MarshalIndent's layout, the encoder's trailing newline.
- **XML** (`virt`): MarshalIndent's layout and escaping (`&#34;`, `&#xA;`, ...), attributes in Go's struct order.
- **Text**: `%q` with Go's IsPrint table, Go's `unicode.IsControl` and `Cf`, errno texts as Go writes them ("no such
  file or directory"), `strings.ToValidUTF8` (a run of bad bytes is one U+FFFD) for guest output.
- **netip**: parsing, masking and printing of addresses and prefixes, the 4-in-6 rules of the scope predicates.
- **HTTP**: Go 1.27's mux: a path that is not clean is redirected with **307**, a path served under another method gets
  405 with `Allow` (GET implies HEAD), anything else `404 page not found`, wildcards matched on escaped segments.
- **Accounts**: the Go limbo is built with CGO_ENABLED=0, so it reads /etc/group and /etc/passwd itself; so does the port.
- **Processes** (`limbo wine`): bwrap is started as Go's os/exec starts it, with fork and execve (no shell fallback for a
  file without `#!`, which std's execvp would try), its own process group, descriptors 3 and 4 and the data files from 5,
  every signal back to its default and an empty mask in the child; SIGINT, SIGTERM and SIGHUP are read from a signalfd
  while a sandbox runs (Go's signal.Notify) and what is left unread is dropped afterwards (Go's channel).
- **Processes**: the exec error texts (`exit status 1`, `signal: killed`, `exec: "virsh": executable file not found in
  $PATH`), a command killed by its deadline or a stop read as exit -1 with no error (as Go's ssh executor reads it).

## Proof

- **The Go tests, carried over as fixtures.** Each package's `parity_test.go` (at the pinned commit: "The Go side") recorded what the Go code answers;
  `LIMBO_PARITY_UPDATE=1 go test ./internal/... ./cmd/limbo -run Parity` writes `testdata/parity/*.json`, and without the variable
  the Go test fails when a fixture is out of date. The Rust tests run the same files:

  | Fixture | What | Comparisons |
  | --- | --- | --- |
  | `manifests.json` | manifest.Parse on 85 variants (every case of the manifest tests and more), and for each one that parses the domain and network XML, addressing, nft rules (apply, restrict, release), the cloud-init seed, the names; a Windows domain; the UFW rules; the seeds `limbo seed` writes (cloud-init with the guest's host key pair, a Windows guest's answer file, first-logon script and keys, with every option and refusal) | 1,566 |
  | `flows.json` | prefixes, scopes, packet parsing (crafted and random), whole and damaged netlink reads, the bind requests, acks, 30 generated aggregator sequences with a clock | 520 |
  | `quarantine.json` | clean() and 25 generated store sequences (records, errors, holding, the list, the files on disk) | 3,140 |
  | `engine.json` | 184 scenarios: up for eight manifests with each step failing in turn, down, holds, release, defined, held and condemned guests, wrong images, subnets taken; every command line and stdin, event, error and file | 1,598 |
  | `api.json` | 14 scenarios, 172 requests on the four sockets with the Go handlers' own fakes: route tables, the mux, holds, verdicts, a failing audit log, runs and their codes, decoder errors, the password switch | 736 |
  | `hostpolicy.json` | 216 fake hosts (each a sysfs tree, os-release, host policy, boot id, approval file, reboot markers, open files, drivers; made a real folder by the Rust test): every case of the hostpolicy tests, then 120 generated hosts; Check, Ready, Standing, HostID, Before/After with every refusal's kind and text; the daemon restarted (the run folder emptied), the host rebooted (a new boot id) and Clear between questions, both markers' bytes after every step; 21 hand-written and damaged markers, 7 boot ids | 5,241 |
  | `cli.json` | the pieces of the socket-client commands' output (the CLI port, step 6): Go's flag parsing with its messages and usage on two flag sets and 39 argument lists, text/tabwriter (67 texts), json.Indent, a RawMessage's compaction and member lookup (21 documents), `%v` of floats, RFC3339, the CLI's sizes; `limbo report --since` (parseSince) from a fixed time on 3,056 inputs | 7,028 |
  | `tz.json` | Go's local time zone as `limbo image list` shows times (`cmd/limbo/parity_tz_test.go`): 47 TZif files made up for it (versions 1-3, transitions, first-zone rules, broken files, and 29 POSIX TZ footers: rules J, n and M, offsets and times out of the usual range, malformed ones) read by LoadLocationFromTZData, 27 times looked up in each | 4,367 |
  | `cliclient.json` | the CLI's HTTP client (`cmd/limbo/parity_client_test.go`): 317 request URLs `"http://limbo"+path` as http.NewRequest reads them (error, request target, the URL as an error writes it), 928 Locations resolved against them (userinfo, IPv6 literals, ports, dot segments, opaque and scheme-only references), 68 responses as http.ReadResponse reads them (status lines, MIME headers and continuations, Content-Length, chunked bodies and their errors, trailers, 1xx), 35 times as Go 1.27's encoding/json reads them | 7,449 |

  | `wine.json` | the Wine backend's parts that do not touch the host (`internal/wine/parity_test.go`): 1,026 share checks (two sets of Limbo's folders, three homes, sources that differ from the path), 606 Merges of a profile and the command line against a folder tree made for the test (symlinks absolute, relative, chained, looping and dangling, a named pipe, a file where a folder is expected), 316 sandboxes for hand-written and 70 generated hosts (with SetChdir, WithEnv and the whole command), 308 trace splits (Go's 64 KiB chunks, limits at and around their edges), 216 X authority filters (crafted, damaged, generated), 210 dry runs against the tree, 56 profiles and 20 profile files (modes, sizes, links), names, folders, ShimPrefix, the run record, the prefix record and prefixArch's scanner limits, the lock's message, ensureDir, the pruning of run folders | 3,031 |

  **All 34,676 comparisons equal.** Mapping to the Go test functions of serve's packages: the manifest, virt, policy,
  provision and hostfw tests' inputs are all in `manifests.json`; the flows and quarantine tests' scenarios are in theirs
  plus generated ones; the engine tests' scenarios in `engine.json`; `TestRouteTablesPerPrincipal`, the open, verdict,
  close, oversized-body, agent-error, profiles, sample-run and Settings-switch tests in `api.json`. The runs, instances,
  exchange, license, settings and image-proof tests (which need a real folder, a clock or a running daemon) are covered
  by the differential run below instead of fixtures; every hostpolicy test is a case of `hostpolicy.json`.
- **The differential run** (`rust/parity/daemon-differential.py`): the Go and the Rust daemon, each in its own user,
  mount and network namespace (root inside, nobody outside; /etc/limbo a private empty bind mount; loopback only), with
  fake virsh, qemu-img, nft, ssh, xorriso, ufw and clamscan on PATH that record what they are asked. The same 114 steps
  (109 answers) on admin.sock, control.sock, agent.sock and user.sock: registering instances (and refusals), the Settings
  page's changes within bounds, starting and stopping, the exchange outbox (a clean file streamed out, an EICAR file
  held, paths that climb out), holds raised by Heimdall and verdicts, condemned guests, licenses (masked, revealed,
  refused), validation runs (plain, with a bundle, a non-zero exit, output cut at the limit, binary output, an ssh
  failure, a command timeout, a run stopped by containment), refused profiles (malformed, kept, image missing or
  altered), a sample run, the containment lock, the password switch, and NFLOG packets from real nft rules in the
  namespace (flows, refusals, probes, a scan). **Result: no difference** in the answers (status, type, body), the 174
  events of events.jsonl, the 641 host commands with their input, the 16 state files with their modes and the startup
  messages, once times,
  ids, pids and the scratch folder are normalised. Sockets made with the same modes, removed at exit, exit status 0.
  Then the passthrough phase (2026-11-11, "The reboot-needed marker and restarts" below): a made-up host bound over the
  real one inside the namespace, a run whose device stays on vfio-pci, two restarts with the run folder emptied, a new
  boot id; besides agreeing, both daemons must refuse with `reboot_required` after each restart and allow after the
  reboot (the script checks it; the build before the fix fails it, Go and Rust alike).
- **The CLI differential** (`rust/parity/cli-differential.py`; "How the CLI differential fakes the host" below): the
  Go and the Rust binary on the same arguments, environment, stdin, files and scripted socket answers, comparing stdout,
  stderr, exit status, requests and files. 2026-11-15: **1,046 cases, 5,230 comparisons, no difference** on this PC
  (where nft cannot load log rules, so the net watch cases run without packets); in CI, with real NFLOG packets and
  the usbmon stand-in required (`--require-all`), **1,049 cases, 5,245 comparisons, no difference** (run 43792882719,
  86a479f), and again against the Go build from the pinned commit after the deletion. `net_cases` (16): argument errors, binding without the
  right to, then in a user and network namespace the real nft's log rules for group 7213 on loopback and the daemon
  differential's traffic (flows, refusals, an IPv6 packet, a scan), a time limit, SIGTERM, SIGINT, limits that wrap.
  `capture_cases` (30): every refusal before a recording (arguments, root, the manifest, the output, `--seconds`, a
  device not plugged in or twice, two buses, no usbmon and the modprobe it runs), then recordings: `usbmon_fake` starts
  the command under a seccomp filter that hands exactly the MON_IOCX_GETX ioctl to it (a user notification) and
  answers from the case's script, writing the event's header and data into the caller's buffers with
  process_vm_writev, or an errno, or a signal; every other call reaches the kernel. The pcap files are compared byte
  for byte: another device's events on the same bus never written, empty, short and oversized data (65,536 bytes
  offered by both), a header claiming more than was captured, times before 1970 and negative microseconds, EINTR,
  EAGAIN, an error mid-way, SIGINT, SIGTERM, the hand-over to SUDO_UID.
- **Properties** (`tests/properties.rs`): the Kani harnesses' claims exhaustively (control.sock and agent.sock have no
  route outside their restrict-only sets for every one of the 32 combinations of services; user.sock never has a
  verdict, close, down, settings, instance-registry or license-key route); any path and method on control.sock or
  agent.sock reaches only allowed routes (proptest, 2,000 cases); route tables well formed; a raise never lowers;
  gojson agrees with serde_json on valid documents; only Labyrinth ever hands over a device (proptest, 300 fake hosts
  with every device listed, eligible and approved: LykanOS and its old ID refused by name, any other OS or a missing
  ID refused, Labyrinth allowed and ready).
- **Fuzzing** (`rust/fuzz`, nightly): `http_request` (any bytes on any socket: no panic, and control and agent reach only
  their routes), `json`, `manifest` (parses, validates and round-trips, or is refused; the XML and rules are made),
  `nflog`. Their bodies also run on stable in `tests/properties.rs` on every `cargo test`.
- **Kani** (`src/api.rs`, `src/quarantine.rs`, `#[cfg(kani)]`): `control_and_agent_have_no_loosening_route`,
  `user_sock_never_has_verdicts_or_root_routes`, `a_raise_never_lowers`. Kani is not installed here; run with
  `cargo kani -p limbo`.

## Measured (2026-11-10)

Both daemons in the differential harness (same namespaces, same fake tools, release builds, this PC):

| | Go | Rust |
| --- | --- | --- |
| after start: RSS | 13.5 MB | **3.3 MB** |
| after start: PSS | 13.5 MB | **1.3 MB** |
| after the script (108 answers, 11 runs, NFLOG): RSS | 19.1 MB | **4.1 MB** |
| after the script: PSS | 19.1 MB | **1.9 MB** |
| peak (VmHWM) | 21.1 MB | 4.8 MB |
| threads idle | 10-15 | **1** |
| CPU during the script | 7 ticks | 5 ticks |
| context switches during the script (all threads) | 5,334 | **159** |
| idle 60 s: CPU / context switches | 0 ticks / 2 | 0 ticks / 0 |
| binary | 9.0 MB (stripped, CGO off) | 1.5 MB |

The Go figures here are lower than the 18.8 MB the installed daemon shows after days of use; both grow a little with
use. The Rust daemon keeps one malloc arena for all its threads and hands freed heap back (malloc_trim) when the last
open connection ends and when a run ends; before that change it stayed at 6.3 MB RSS after the script. Idle, neither does anything: both sleep in the kernel until a socket or the NFLOG group wakes them.

Installed on my PC (limbo-git 1.0.0-10, the package's `/usr/bin/limbo`, no drop-in): 4.1 MB resident and 1 thread after
ten hours of `limbo serve` (2026-11-19).

Found by these runs and fixed before the numbers: guest output with several bad bytes in a row (Go writes one U+FFFD per
run of bad bytes, the first build one per byte); a command killed by its deadline or a stop (Go reads it as exit -1 with
no error); a command's end was noticed only every 25 ms (now a pidfd in poll(2)).

## Differences from Go, on purpose or accepted

- A request path with bytes that are not UTF-8 (`%ff`): Go keeps the byte and `%q` shows `"\xff"`; the port reads it as
  U+FFFD. Such a name is refused by every name rule either way; only the refusal's text differs.
- A file name in an outbox that holds a real U+FFFD character is not listed by the port (it cannot be told from a
  replaced byte); Go lists it.
- (Fixed in Go 2026-11-11: `license.Check` for a Windows guest with both files missing named either file, by map
  order; both now name the ISO first. Likewise `limbo seed` wrote its files in map order; both now write them in one
  order, which decides what a failed write leaves.)
- (Checked 2026-11-11: a type error inside image-proofs.json reads `recordFile.images.0.dev` in Go 1.27 and in the
  port; `limbo image list` shows it and the CLI differential compares it.)
- One request per connection (`Connection: close`); Go keeps connections open. Limbo's clients (the Go CLI, Heimdall,
  Sarina's Go client, the Settings page) open one per request. A chunked body is read (Go reads it too).
- Over 128 connections at once wait for a slot (Go has no bound).
- The CLI's client (cli/client.rs) sends no `User-Agent` and no `Accept-Encoding: gzip` (Go's transport adds both; no
  Limbo daemon reads them, and the port could not undo a gzip answer). It opens a connection per request; Go reuses an
  open one. A Location to `https://` is refused as an unsupported scheme (Go would try TLS over the unix socket, which no
  daemon speaks). A socket read error other than the end or the deadline reads `read: <errno>` (Go names the addresses;
  not reproduced). Bytes after a complete answer are dropped silently (Go may log "Unsolicited response received on idle
  HTTP channel", time-stamped, when its read loop sees them first). An answer's status line that is not UTF-8 reaches
  "server returned ..." with U+FFFD. An argument or one of the variables the five commands read (SUDO_USER, USER,
  PKEXEC_UID, SUDO_UID, SUDO_GID, and for the manifest commands HOME, LIMBO_STATE_DIR and TMPDIR) that is not UTF-8
  hands the command to the Go limbo. The 60 s client timeout is in
  the port with Go's texts but not exercised by the differential run (it would take a minute per case).
- `limbo seed`: the output of a failing ssh-keygen or xorriso reaches the error with each byte that is not UTF-8 as
  U+FFFD (Go prints the bytes). `limbo report` and `limbo analyze`: the time now (the report's "Generated", a --since
  duration, analyze's deadline) is the one input the differential run cannot hold equal; the report's lines that show
  it are normalised there, and `parseSince` is pinned from a fixed time by `cli.json`.
- `limbo setup`'s question reads stdin through a buffer, as Go's does, but Go's holds 4,096 bytes and the port's
  8,192: with more than 4 KB waiting on stdin, the programs setup runs afterwards (pacman, systemctl) find less of it
  left in the port. Nobody pipes that much into setup.
- `limbo wine`: an environment variable or the working folder that is not UTF-8 hands the command to the Go limbo (it
  reads the whole environment). An `#arch=` line of a prefix's system.reg, an /etc/passwd or /etc/group line, or a
  symlink target under /, /etc/localtime or /sys/class/drm with bytes that are not UTF-8 reads them as U+FFFD (Go keeps
  the bytes; Wine and the system write none). A profile that shrinks between its stat and its read: Go fails with
  `EOF`, the port reads what is there (a race only). The environment bwrap gets is the same list in the same order.
- **A command line that is not UTF-8** (2026-11-15, with the Go build gone): refused with exit status 2 and `limbo:
  argument N is not UTF-8 (...)`, the daemon's included (never a panic); so is one of the variables the commands read
  (SUDO_USER, USER, PKEXEC_UID, SUDO_UID, SUDO_GID, HOME, LIMBO_STATE_DIR, TMPDIR, WAYLAND_DISPLAY): `limbo: $NAME is not
  UTF-8; limbo reads it`. Go took any bytes. `limbo wine` reads the whole environment: a variable that is not UTF-8 is
  refused only when wine reads it or hands it to the sandbox (the probe's, the folders', the shim's and the caller's
  variables, every `XDG_` one and every name the sandbox passes through); any other is left out, which is what Go's
  sandbox did with it too. A working folder that is not UTF-8 is refused for `limbo wine`. The practical case is a
  Windows program whose file name is not UTF-8 (an old zip): rename it, or start it from a folder whose path is UTF-8.
- `limbo capture`: what reaches the pcap file is the same bytes; a write error is reported as Go's `write PATH: ...`
  at the same buffer boundaries (bufio's 4 KiB), not exercised (no full disk in the harness).
- JSON error paths now follow Go 1.27 everywhere (the document's own struct name, the path as the document spells it,
  array indexes); the image-proofs.json entry above was written before that and was not checked again.

## Changed since the Go build left

Limbo goes on after the port; the Go limbo of the pinned commit stays the referee for everything that existed then. A
deliberate change to text the fixtures or the differential runs compare is listed in `INTENDED` (the same pairs in
`rust/limbo/tests/common/mod.rs` and both `rust/parity/*-differential.py`): Go's text on the left is read as the new one
before comparing, so nothing else may differ. New behaviour that Go never had (a new mode, a new event kind, a new key in
an answer) needs no entry when no fixture or case reaches it.

- 2026-11-18, network mode `sinkhole` (docs/SINKHOLE.md): the manifest's mode list in its error, the Settings page's
  refusal and `limbo instance`'s usage and flag help name `sinkhole`; a sealed sample profile may be `none` or `sinkhole`,
  and the refusal's remedy says so.
- 2026-11-24, the flows' "first time" memory outlasts a restart (`flows-seen.json` in the state folder, keyed by each
  guest's manifest): the daemon differential leaves that file out of its comparison of the state folder (Go never wrote
  it); the events are compared as before.

## The switch: why not a week of shadow mode

Heimdall's port ran a week beside the Go daemon, reading the same sources and writing its own alert log. Two Limbo
daemons cannot do that, and must not try: each binds `/run/limbo/*.sock` (one would take the other's sockets), each
**destroys the guests of unfinished runs at startup** (`ReapOrphans`: a second daemon starting would tear down the
validation runs the first is executing), only one process can bind NFLOG group 7213, both would write events.jsonl
(Heimdall would see every event twice), and both would act on the same libvirt guests and nftables tables (a hold
applied by one, a release by the other). So instead of a live shadow:

1. **The differential run** above: both daemons, identical traffic, nothing real touched. Done: no difference.
2. **The rehearsal on a copy of this computer's real state** (`--from-host`, root, needs nothing stopped): the state
   folder (guests' disks left out), profiles, instances, licenses and the password switch are copied into a root-only
   scratch folder, each daemon starts from the copy in its own namespaces with fake host programs, and both are asked
   what the Settings page, Heimdall and Sarina read (status, instances, holds, profiles with the real images' proofs,
   licenses masked, outboxes, whether each guest exists). It proves the Rust daemon reads exactly what the Go daemon
   wrote, on the real files, and changes nothing.
3. **The real-guest scripts against the Rust daemon** (`LIMBO_RS=...`), as for any change to these packages.
4. **A direct switch** with the Go daemon one command away. Switching is a daemon restart, which Limbo already handles:
   the state files are shared, running guests keep running, and the startup reap is the same in both.

## Rerunning the checks (root for the second step)

```bash
cd ~/Documents/Github/Limbo && git pull
(cd rust && scripts/nicecargo.sh build --release --locked)
sh rust/parity/go-limbo.sh /tmp/limbo-go   # the Go referee, from the pinned commit ("The Go side")

# 1. (no root) the differential run again
python3 -I rust/parity/daemon-differential.py --go /tmp/limbo-go --rs rust/target/release/limbo-rs --out /tmp/ld --idle 60

# 2. the rehearsal on a copy of the real state (read-only, both daemons in namespaces, nothing stopped; its scratch folder
# with the copies is deleted at once), then each real-guest script twice, with the Go daemon (baseline) and with limbo-rs;
# summary.txt lists every check that differs between the two
sudo bash scripts/rust-checks.sh /tmp/limbo-go rust/target/release/limbo-rs ~/limbo-rust-checks-2
# (integration-linux-guest.sh does not use the daemon; integration-systemd.sh installs and removes files: test machine only)
# One script against the Rust daemon alone: sudo LIMBO_RS="$PWD/rust/target/release/limbo-rs" bash scripts/integration-chain.sh
```

The switch itself was a systemd drop-in on 2026-11-10, and the package since 2026-11-11 ("Packaging"). Restarting
`limbo.service` while a validation run is executing destroys that run's guest (the startup reap, as with any restart):
restart when Sarina is not running one.

## Packaging (2026-11-11; one binary since 2026-11-15)

**Since 2026-11-15** the package installs one binary, `/usr/bin/limbo` (limbo-rs), and builds no Go (`makedepends`
lose `go`; `check()` runs the Rust tests only; Labyrinth's two limbo-git recipes the same). `limbo.install` says on
upgrade that a hand-installed `/usr/lib/limbo/limbo-go` (no package's file) can go. What follows is how it was from
2026-11-11, kept for the hosts that switched by hand then.

From 2026-11-10 my PC ran the Rust daemon through the drop-in of step 4 above. Since 2026-11-11 the packages ship it:

- **`packaging/arch/PKGBUILD`**: `/usr/bin/limbo` is limbo-rs: the daemon, every ported command, and the dispatcher that
  hands `net watch`, `capture` and any command line that is not UTF-8, unchanged, to the Go build at
  `/usr/lib/limbo/limbo-go` (where limbo-rs looks: `main.rs` `go_binary`; `/usr/bin/limbo` itself is skipped, so it
  never runs itself). The packaged `limbo.service` (`ExecStart=/usr/bin/limbo serve ...`), `limbo-image-verify.service`
  and the wine shim keep calling `/usr/bin/limbo`, so no unit changes. `makedepends` gains `rust`, `depends` `gcc-libs`
  (the binary links libc and libgcc_s); `prepare()` runs `cargo fetch --locked`, `build()` `cargo build --frozen
  --release -p limbo --bin limbo-rs`, and `check()` runs the Rust tests too. `LIMBO_RS_NO_GO` is set by the CLI
  differential run only, never by a unit, a package or a script. `limbo.install` says, on upgrade, that a hand-made
  drop-in can go and that the service runs the new daemon only after a restart (it restarts nothing itself).
  `rust/limbo/tests/dispatch.rs` pins the hand-over to Go: before it, a command line that was not UTF-8 made limbo-rs
  panic in `std::env::args()` instead of reaching Go (as `/usr/bin/limbo`, every such command would have failed).
- **Labyrinth's `packages/pkgbuilds/limbo-git`** (built from the local Limbo checkout) and the store's copy
  (`profile/airootfs/usr/share/labyrinth/pkgbuilds/limbo-git`, built from GitHub): the same changes, mirrored in
  Labyrinth_OS the same day. The ISO's package list needs nothing new (same package name).
- **On a host that switched by hand** (my PC; root). The hand-installed `/usr/lib/limbo/limbo-go` is no package's file,
  so pacman needs `--overwrite` for it; `/usr/lib/limbo/limbo-rs` is not in the package and stays until removed. Nothing
  restarts until the `restart` line; the drop-in goes only once the packaged unit is in place:

  ```bash
  sudo pacman -U --overwrite /usr/lib/limbo/limbo-go limbo-git-<version>-x86_64.pkg.tar.zst
  sudo rm /etc/systemd/system/limbo.service.d/rust.conf && sudo rmdir --ignore-fail-on-non-empty /etc/systemd/system/limbo.service.d
  sudo systemctl daemon-reload
  systemctl show -p ExecStart --value limbo.service      # /usr/bin/limbo serve ...
  sudo ls -A /var/lib/limbo/state/runs                     # empty: no validation run for the restart to destroy
  test -e /run/limbo/passthrough.blocked && echo "reboot instead: the old build's marker is only here, and a restart empties /run/limbo"
  sudo systemctl restart limbo.service                     # not during a validation run (the startup reap)
  sudo rm /usr/lib/limbo/limbo-rs                          # the hand-installed daemon, named nowhere now
  limbo rs-version; limbo version; limbo doctor; systemctl is-active limbo.service
  pid=$(systemctl show -p MainPID --value limbo.service); ps -o args= -p "$pid"; grep -E '^(VmRSS|Threads)' /proc/$pid/status
  ```

  Back to the Go daemon with the package installed (the state is shared; the CLI stays limbo-rs):

  ```bash
  sudo mkdir -p /etc/systemd/system/limbo.service.d
  printf '[Service]\nExecStart=\nExecStart=/usr/lib/limbo/limbo-go serve --state-dir /var/lib/limbo/state --run-dir /run/limbo --profile-dir /etc/limbo/validation\n' \
    | sudo tee /etc/systemd/system/limbo.service.d/go.conf
  sudo systemctl daemon-reload && sudo systemctl restart limbo.service
  ```

  Back to the previous package entirely: `sudo pacman -U` of the old file (pacman's cache), which makes `/usr/bin/limbo`
  the Go build again and removes `/usr/lib/limbo/limbo-go`; then `restart`.

## The reboot-needed marker and restarts (2026-11-11)

**The gap.** After a run, Limbo checks every passed-through PCI device is back under the host driver it had. If one is
not, a marker blocks every later passthrough start until the host reboots (a card that did not come back must not be
handed out again). The marker lived only in `/run/limbo`, a tmpfs, so that a reboot removes it. But `limbo.service` has
`RuntimeDirectory=limbo`, and systemd empties that folder at **every stop** of the service: any restart of the daemon
(a package upgrade, `systemctl restart`, Restart=on-failure) lifted the block without the reboot. Go and Rust alike.

**What I chose.** The marker that counts is now in the state folder, `/var/lib/limbo/state/passthrough.blocked`
(persistent, root-only, 0600), and names the boot it was written in:

```
boot_id 6f1c0a52-3c1e-4b8e-9d0a-2b7f4e5c8a11
device 0000:03:00.0 is bound to "vfio-pci" after teardown
```

The id is the kernel's `/proc/sys/kernel/random/boot_id`, a random UUID made at every boot. The marker **counts unless
it is proven to be from an earlier boot**: its id and this boot's are both well-formed (lower-case 8-4-4-4-12 hex) and
differ. Everything else counts: a marker that cannot be read, is damaged or empty, the old one-line form, `boot_id
unknown` (written when the boot id could not be read), a boot id this host cannot read. Only `sudo limbo passthrough
clear` (after recovering the device by hand) or a provable reboot ends it. A marker from an earlier boot stays on disk,
inert, until the next one overwrites it or `clear` removes it. The run folder's marker is still written (it covers a
state folder that cannot be written, until the service stops) and still counts while there; `clear` removes both.
`limbo up` (no daemon, `--state-dir`) and `limbo passthrough` read the same state folder's marker.

**Why not `RuntimeDirectoryPreserve=restart`** (the other option): it keeps /run/limbo across `systemctl restart` and
Restart=on-failure only; a `stop` then `start`, or a unit edited between them, still empties it. `=yes` would keep the
folder until the reboot, but the block would then rest on one line of one unit: a drop-in, another unit, or a `limbo
serve` started by hand (the integration scripts do) would not have it, and anything that empties /run/limbo would lift
the block. The boot id is the code's own proof that a reboot happened, whoever started the daemon, whatever the unit
says. Security over convenience: what cannot prove a reboot keeps passthrough off. **The unit is unchanged**, so the
Labyrinth `limbo-git` recipes need nothing. Stale sockets were never the problem: both daemons remove a socket file
left at a socket's path before binding (and refuse anything that is not a socket), as before.

**Tests.** `hostpolicy.json` (Go writes it, Rust compares): restart, reboot and clear between questions, both markers'
bytes after each step; marker set, restart, still blocked; new boot id, ended; a new failure after the reboot names the
new boot; 21 damaged or hand-written markers, 7 boot ids (empty, upper case, short, doubled, padded with Unicode spaces
Go's TrimSpace removes); a restart, reboot or clear inserted into a third of the generated hosts. A Rust mutation that
lets a restart lift the block fails 48 of the 5,241 comparisons. Go unit tests:
`TestBlockOutlastsRestartEndsWithReboot`, `TestDamagedMarkerCountsUntilCleared`. The CLI differential: `limbo
passthrough status`, `approve` and `clear` with state markers of this boot, an earlier boot, damaged ones and an empty
or damaged boot id (a made-up boot id bound over /proc/sys/kernel/random/boot_id in the namespace), both markers, a
state marker that is a full folder (the whole run: 1,000 cases, 5,000 comparisons, no difference). The daemon
differential: the passthrough phase (above), no difference.

**On my PC.** The running daemon (built before this) keeps its marker only in /run/limbo, which the restart that
installs this build empties: before that restart, `test -e /run/limbo/passthrough.blocked` must be false (if it is
there: reboot instead of restarting). From this build on, restarts keep the block.

## The owner's first run (2026-11-10, release build of bea73d9): every failure was the scripts' or this computer's

| Failure | Cause | Fix |
| --- | --- | --- |
| rehearsal: `can't open file .../daemon-differential.py: Permission denied` | `--from-host` re-ran the script, and the daemons, from the repo inside `unshare -rmn`: root in a user namespace has no power over files outside it, and the home folder is 0700 | the script and both binaries are copied into the scratch folder first and run from there |
| quarantine: "switch route on user.sock" | the script wanted 404; Go's mux answers **405** (user.sock serves GET /v1/settings, not POST), as `internal/api/settings_test.go` already allows | 404 or 405; the differential run now sends that request to both daemons (405 from both) |
| quarantine: "a non-disposable profile was offered" | a grep for the name in the whole answer, which since 2026-10-06 names it in `skipped` | checks `profiles` (not there) and `skipped` (there, `profile_invalid`) |
| chain: false alert "tailscale is installed" | Heimdall's newer host-wide detectors (remote-access, hardening) report this computer's state at start | only alerts about the guest or Limbo count; the others are shown |
| chain: heimdalld `permission denied` on /var/lib/heimdall | the test's unprivileged heimdalld used Heimdall's default state paths | every state and intelligence path in the test folder; the connection, listen and firewall watchers off |
| chain: advisory, model.jsonl, fenced prompt | the installed sarina-service already listens on 8899: the script's Python Sarina could not start and the health check reached the installed one | Sarina's Go binary (`/usr/bin/sarina`) by default, the test's own ports (18899, 18998, 18000), a stop if one is taken, the health check tied to the started process |
| chain: "now UNFILTERED" | UFW (on by default here) drops a guest's packets to the host whatever Limbo does, so deleting Limbo's table opened nothing | while UFW is active a temporary UFW rule (removed at exit) lets the guest's bridge reach the test's port: Limbo's own table is then the one barrier, which the healthy check also proves |
| sarina: 11 of 15 | the script still defaulted to the Python service (`No module named 'sarina'`) | Sarina's Go binary by default (`scripts/it-common.sh`) |

The rerun with `scripts/rust-checks.sh` (2026-11-11): rehearsal NO DIFFERENCE; quarantine 71/71 and sarina 15/15 with
both daemons; chain 32/32 with limbo-rs but 27/32 with Go, every difference a Sarina-advisory check of the **Go** run.
Cause: the script started the test heimdalld inside a subshell (`as ... &`), and killing that subshell at exit left
`runuser` and heimdalld running. Three were still running afterwards (from the first run, the Go rerun and the Rust
rerun), all watching the same event log and control socket. In the Go rerun the one from the first run, with the old
configuration (Sarina on the installed 8899, Heimdall's default /var/lib/heimdall paths: the `wifi results ...
permission denied` lines came from it, writing into the new run's truncated heimdall.err), opened the quarantine
first, so the advisory went to the installed Sarina and never came; in the Rust rerun a leftover with the new
configuration happened to answer. Fixed: heimdalld is started with `exec runuser` (the kill reaches it) and every
heimdalld of the test user is stopped before and after (`stop_test_heimdalld`); the run checks there is exactly one;
the advisory wait is 60 s and a failure shows this run's heimdalld and Sarina lines and the model's request count.
`integration-real-model.sh` had the same leak and default paths: fixed the same way (`heimdall_isolation`).

**The Sarina parts of these scripts could not have worked from 2026-10-05 until 2026-11-11** unless `SARINA_BIN` was
set by hand. Without it, `integration-chain.sh`, `integration-sarina.sh` and `integration-real-model.sh` started
`python3 -m sarina.service` from the Sarina repo, and Sarina deleted that module (`sarina/service/`) on 2026-10-05 when
it moved to Go. The service never came up, so every check after "Sarina's service is up" in those runs is about a
service that was not there (or, for chain, the installed one on 8899). `it-common.sh` defaulted to `/usr/bin/sarina` from
2026-11-10 (chain and sarina); `integration-real-model.sh` kept the Python default until 2026-11-11. Since 2026-11-11
none of them has a Python path: all three run `"$SARINA_BIN" service` with the same arguments (`--port`, `--token`,
`--base-url`, `--model`, `--api-key`, `--session-dir`, `--scratchpad-root`, all flags of Sarina's
`go/service/command.go`), `SARINA_BIN` being the one given or the installed `/usr/bin/sarina` (the binary that
`sarina-service` links to), and `pick_sarina` stops the script when there is neither.

`scripts/rust-checks.sh` runs every script with the Go daemon and with limbo-rs and lists the checks that differ, so a
failure of the script or the computer is told apart from one of the port.

## How the CLI differential fakes the host

The image cases that need root's files run under `unshare -r` (uid 0 in a user namespace, so the files made for the case
are root's there; never real root), with `--state-dir` in the work folder and `--i-know`; a case's `prep` writes the
record file with each image's real device, inode, size and times; 16 values of $TZ. doctor and setup run under `unshare
-rm` with /etc/limbo, /var/lib/limbo and /usr/lib/sysusers.d bind-mounted from the case's own folders (`nsrun`), and
PATH holding only fake programs (pacman, systemctl, systemd-sysusers, groupadd, getent and the runtime's commands, each
logging its arguments): nothing real is installed, enabled or read. The guest commands run the same way (`NSRUN_ACT`),
with a tmpfs on /run whose /run/limbo/user.sock is the case's scripted socket (a person's launch asks it, never the real
daemon), and for a person's launch a second user namespace that makes the command uid 1000 again; virsh, qemu-img, nft
(logging the rules it is fed), ufw, ssh, waypipe and xfreerdp3 are fakes: no guest, firewall, network or display is
touched. passthrough runs there too, with /etc/os-release, the host policy and /sys/bus/usb/devices and
/sys/bus/pci/devices bound over by made-up ones (no device of this computer is read) and the typed answer from a pty.
`wine` (`wine/`, internal/wine file by file, and `cli/wine.rs`; 23e0976 and the commit with this note): its pure parts
pinned by `wine.json` (3,031 comparisons), then the dry run and real runs on a made-up host (`NSRUN_WINE`): an overlay
puts Limbo's fake bwrap, wine and wineserver over /usr/bin (nothing of the host changes); /dev holds only the usual
nodes and made-up graphics nodes (/dev/null bound over each name), /sys, /opt and /etc are the case's own (made-up
accounts, /etc entries, a Vulkan manifest naming a folder under /opt), /tmp is the namespace's own with the case's X11
socket folder; the Wayland, PulseAudio and PipeWire sockets, ~/.Xauthority and the PulseAudio cookie are made up in the
case folder; a nested user namespace makes the command uid 1000. The fake bwrap logs its arguments, the environment and
the data files on its descriptors and acts the sandbox's part from the case's fake.ctl (the started byte, the prefix
made, output and Wine's trace lines, an exit status, a stop request sent to limbo and the answer read from descriptor 3,
a second signal, a stop ignored until the 10 s grace kills it); it never starts anything, and nothing of this computer's
display, sound, graphics card or accounts is read. 123 cases: 74 dry runs (every refusal before a run, shares, profiles,
the host's variations) and 49 runs (making a prefix, setting its Windows version, every setup and sandbox failure, the
trace split, stops by SIGTERM, SIGINT and SIGHUP, the kill, root, missing bwrap or Wine, a bwrap without an interpreter,
a busy prefix, an unwritable state folder, a full event log, the shim).

limbo-rs gets `LIMBO_RS_NO_GO=1` there, so a command it does not run itself fails instead of reaching a Go limbo.

## Running the tests

```bash
cd rust
scripts/nicecargo.sh test --offline          # every fixture, the properties, the fuzz bodies, dispatch, packaging
scripts/nicecargo.sh clippy --all-targets
scripts/nicecargo.sh build --release --bins --example usbmon_fake
cd .. && sh rust/parity/go-limbo.sh /tmp/limbo-go    # the Go referee from the pinned commit
python3 -I rust/parity/cli-differential.py --go /tmp/limbo-go --rs rust/target/release/limbo-rs --out /tmp/lcd
python3 -I rust/parity/daemon-differential.py --go /tmp/limbo-go --rs rust/target/release/limbo-rs --out /tmp/ld --idle 5
```
