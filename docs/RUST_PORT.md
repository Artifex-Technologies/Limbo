# The Rust port of `limbo serve`

I want as much of the ecosystem as possible in Rust, for lightness and smoothness while I game and run a local model.
`limbo serve` is Limbo's always-on part, so it goes first; Heimdall's port (its `docs/RUST_PORT.md`) is the model. The
Go daemon measured 18.8 MB RSS idle on my PC; the target was about 3-5 MB.

The CLI is being ported command by command. limbo-rs runs these itself (when their arguments and the variables they
read are UTF-8): the five socket-client commands (`quarantine`, `settings`, `instance`, `license`, `exchange`) and,
since 2026-11-11, `version`, `validate`, `plan`, `address`, `seed`, `report`, `analyze`, `image`, an unknown command
and no command at all. Still in Go: `up`, `down`, `launch`, `export`, `screenshot`, `capture`, `wine`, `passthrough`,
`doctor`, `setup`, `net`.
`limbo-rs serve` is the daemon; **every other command is handed, unchanged, to the Go binary**
(`$LIMBO_GO_BINARY`, else `limbo-go` beside `limbo-rs`, else `/usr/lib/limbo/limbo-go`, else `/usr/bin/limbo`). The
state files are the contract between the two and are the Go daemon's, in the same formats.

## Status

| Step | What | State |
| --- | --- | --- |
| 1 | every package `serve` uses, in `rust/limbo`: events, quarantine, settings, manifest, virt (XML, subnets), policy, hostfw, provision, disk, image proofs, license, exchange, hostpolicy (the serve side), engine, runs, instances, flows (aggregator + NFLOG socket), the HTTP layer with Go's ServeMux rules, api, serve | **done** (2026-11-10) |
| 2 | the Go fixtures (`testdata/parity`), the properties, fuzz targets and Kani harnesses | **done**: see "Proof" |
| 3 | the differential run of both daemons on the same socket traffic (`rust/parity/daemon-differential.py`) | **done**: no difference |
| 4 | the real-guest scripts against the Rust daemon (`LIMBO_RS=... scripts/integration-*.sh`) | **prepared, needs root**: commands below |
| 5 | the rehearsal on a copy of this computer's real state (`--from-host`), then the switch | **prepared, needs root**: "The switch" |
| 6 | the CLI commands, one by one | **in progress**: the five socket-client commands, then version, validate, plan, address, seed, report, analyze and image (2026-11-11, `cli.json`, `cliclient.json`, `manifests.json`, `tz.json` and the CLI differential run); the rest open ("Resume here") |

## Layout

```
rust/
  Cargo.toml, Cargo.lock      workspace; exact versions (sha2, rustix, libc; proptest and serde_json for tests)
  limbo/src/                  one module per Go package, named in its first line
    gojson.rs, gotext/, gotime.rs   Go's behaviour where Rust's differs (below); from Heimdall's port, extended
    http.rs                   HTTP/1.1 on a unix socket, one request per connection, Go's ServeMux matching
    api.rs                    the route tables (one function), handlers, the Kani harnesses on the tables
    serve.rs                  startup in Go's order, one poll(2) loop, a thread per connection and per run
    main.rs                   `serve`, else exec the Go limbo
  limbo/tests/                parity_* (the Go fixtures), properties.rs (exhaustive claims, proptest, fuzz bodies)
  fuzz/                       cargo-fuzz targets (nightly): http_request, json, manifest, nflog
  parity/daemon-differential.py   both daemons, the same traffic, compared
  scripts/nicecargo.sh        cargo at nice 15
internal/parity/              the fixture writer and the manifest corpus; each package's parity_test.go records Go
testdata/parity/              the fixtures both languages run
scripts/rust-daemon.sh        LIMBO_RS=... makes the integration scripts use the Rust daemon
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
- **Processes**: the exec error texts (`exit status 1`, `signal: killed`, `exec: "virsh": executable file not found in
  $PATH`), a command killed by its deadline or a stop read as exit -1 with no error (as Go's ssh executor reads it).

## Proof

- **The Go tests, carried over as fixtures.** Each package's `parity_test.go` records what the Go code answers;
  `LIMBO_PARITY_UPDATE=1 go test ./internal/... ./cmd/limbo -run Parity` writes `testdata/parity/*.json`, and without the variable
  the Go test fails when a fixture is out of date. The Rust tests run the same files:

  | Fixture | What | Comparisons |
  | --- | --- | --- |
  | `manifests.json` | manifest.Parse on 85 variants (every case of the manifest tests and more), and for each one that parses the domain and network XML, addressing, nft rules (apply, restrict, release), the cloud-init seed, the names; a Windows domain; the UFW rules; the seeds `limbo seed` writes (cloud-init with the guest's host key pair, a Windows guest's answer file, first-logon script and keys, with every option and refusal) | 1,566 |
  | `flows.json` | prefixes, scopes, packet parsing (crafted and random), whole and damaged netlink reads, the bind requests, acks, 30 generated aggregator sequences with a clock | 520 |
  | `quarantine.json` | clean() and 25 generated store sequences (records, errors, holding, the list, the files on disk) | 3,140 |
  | `engine.json` | 184 scenarios: up for eight manifests with each step failing in turn, down, holds, release, defined, held and condemned guests, wrong images, subnets taken; every command line and stdin, event, error and file | 1,598 |
  | `api.json` | 14 scenarios, 172 requests on the four sockets with the Go handlers' own fakes: route tables, the mux, holds, verdicts, a failing audit log, runs and their codes, decoder errors, the password switch | 736 |
  | `hostpolicy.json` | 181 fake hosts (each a sysfs tree, os-release, host policy, approval file, reboot marker, open files, drivers; made a real folder by the Rust test): every case of the hostpolicy tests, then 120 generated hosts; Check, Ready, Standing, HostID, Before/After with every refusal's kind and text | 2,484 |
  | `cli.json` | the pieces of the socket-client commands' output (the CLI port, step 6): Go's flag parsing with its messages and usage on two flag sets and 39 argument lists, text/tabwriter (67 texts), json.Indent, a RawMessage's compaction and member lookup (21 documents), `%v` of floats, RFC3339, the CLI's sizes; `limbo report --since` (parseSince) from a fixed time on 3,056 inputs | 7,028 |
  | `tz.json` | Go's local time zone as `limbo image list` shows times (`cmd/limbo/parity_tz_test.go`): 47 TZif files made up for it (versions 1-3, transitions, first-zone rules, broken files, and 29 POSIX TZ footers: rules J, n and M, offsets and times out of the usual range, malformed ones) read by LoadLocationFromTZData, 27 times looked up in each | 4,367 |
  | `cliclient.json` | the CLI's HTTP client (`cmd/limbo/parity_client_test.go`): 317 request URLs `"http://limbo"+path` as http.NewRequest reads them (error, request target, the URL as an error writes it), 928 Locations resolved against them (userinfo, IPv6 literals, ports, dot segments, opaque and scheme-only references), 68 responses as http.ReadResponse reads them (status lines, MIME headers and continuations, Content-Length, chunked bodies and their errors, trailers, 1xx), 35 times as Go 1.27's encoding/json reads them | 7,449 |

  **All 28,888 comparisons equal.** Mapping to the Go test functions of serve's packages: the manifest, virt, policy,
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
- JSON error paths now follow Go 1.27 everywhere (the document's own struct name, the path as the document spells it,
  array indexes); the image-proofs.json entry above was written before that and was not checked again.

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

## Commands for the owner (root; nothing above was installed or run as root by the session)

```bash
cd ~/Documents/Github/Limbo && git pull
(cd rust && scripts/nicecargo.sh build --release --locked)
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /tmp/limbo-go ./cmd/limbo

# 1. (optional, no root) the differential run again
python3 -I rust/parity/daemon-differential.py --go /tmp/limbo-go --rs rust/target/release/limbo-rs --out /tmp/ld --idle 60

# 2 and 3 in one go: the rehearsal on a copy of the real state (read-only, both daemons in namespaces, nothing
# stopped; its scratch folder with the copies is deleted at once), then each real-guest script twice, with the Go
# daemon (baseline) and with limbo-rs; summary.txt lists every check that differs between the two
sudo bash scripts/rust-checks.sh /tmp/limbo-go rust/target/release/limbo-rs ~/limbo-rust-checks-2
# (integration-linux-guest.sh does not use the daemon; integration-systemd.sh installs and removes files: test machine only)
# One script against the Rust daemon alone: sudo LIMBO_RS="$PWD/rust/target/release/limbo-rs" bash scripts/integration-chain.sh

# 4. the switch: the Rust daemon as limbo.service, the Go one kept for every other command
sudo install -Dm755 /usr/bin/limbo /usr/lib/limbo/limbo-go
sudo install -Dm755 rust/target/release/limbo-rs /usr/lib/limbo/limbo-rs
sudo mkdir -p /etc/systemd/system/limbo.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/lib/limbo/limbo-rs serve --state-dir /var/lib/limbo/state --run-dir /run/limbo --profile-dir /etc/limbo/validation\n' \
  | sudo tee /etc/systemd/system/limbo.service.d/rust.conf
sudo systemctl daemon-reload && sudo systemctl restart limbo.service
systemctl status limbo.service --no-pager; journalctl -u limbo.service -n 20 --no-pager
pid=$(systemctl show -p MainPID --value limbo.service); grep -E '^(VmRSS|Threads)' /proc/$pid/status; sudo grep Pss: /proc/$pid/smaps_rollup
limbo settings status    # the CLI (Go) through the Rust daemon's user.sock

# back to the Go daemon at any time (the state is shared):
sudo rm /etc/systemd/system/limbo.service.d/rust.conf && sudo systemctl daemon-reload && sudo systemctl restart limbo.service
```

Restarting `limbo.service` while a validation run is executing destroys that run's guest (the startup reap, as with any
restart of the Go daemon): switch when Sarina is not running one.

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

`scripts/rust-checks.sh` runs every script with the Go daemon and with limbo-rs and lists the checks that differ, so a
failure of the script or the computer is told apart from one of the port.

## Running the tests

```bash
cd rust
scripts/nicecargo.sh test --offline          # every fixture, the properties, the fuzz bodies
scripts/nicecargo.sh clippy --all-targets
cd .. && go test ./internal/... -run Parity  # the fixtures are current with the Go code
LIMBO_PARITY_UPDATE=1 go test ./internal/... ./cmd/limbo -run Parity # after a deliberate change: rewrite them, review the diff
```

## Resume here

Done: steps 1-3 (above), the scripts and commands for 4 and 5; the CI job (`.github/workflows/rust.yml`: the Go
fixtures current, fmt, clippy, tests, the differential run with the real nft for NFLOG, cargo-audit weekly and per
change; green since run 42950117164); the owner's first run read and every failure traced to the scripts (table above).
Next, in order:

1. Rerun done 2026-11-11 (rehearsal NO DIFFERENCE, quarantine 71/71 and sarina 15/15 with both daemons; chain's Go-only
   failures were leftover test heimdallds, fixed in 8531da0): integration-chain.sh once more with both daemons, then the
   switch (drop-in) and the Rust daemon's figures after it. The packages' side is on branch `package-rust-daemon`
   ("Packaging"): merge it, mirror it in Labyrinth's limbo-git, and follow the steps for a host that switched by hand.
2. (hostpolicy done: `hostpolicy.json`.) Carry over the runs tests that use a fake clock and executor (`internal/runs/*_test.go`) as fixtures; today the differential run covers runs end to end, not each branch.
   Plan: `internal/runs/parity_test.go` with a runner that fails by line prefix as `engine/parity_test.go` words it
   (`<line>: exit status 1: <stderr>`; the Rust side builds `CmdErr` with the same text, `not_found` for
   exec.ErrNotFound), a fake executor (out, errOut, exit, truncated, an error that is or is not errConnection, block
   until the command timeout), the profile variants of `setup()`, and per scenario: the Start error (code, message,
   remedy), the finished Result with id and times normalised (`r00000001`...), the command lines per run, the events
   (kind, guest, detail) and the files left under state/. Scenarios needing a caller's context (boot timeout through
   ctx, cancel) stay with the differential run: the Rust `Manager::start` takes none.
3. Done 2026-11-11: the socket-client commands in Rust, dispatched by limbo-rs. `flags.rs`, `tabw.rs`, `text.rs`
   (`cli.json`); `url.rs` and `client.rs` (net/url and net/http's client as the CLI uses them: URL parsing and escaping,
   the request as the transport writes it, http.ReadResponse, redirects, Go's error texts; `cliclient.json`, 7,449
   comparisons) in 18e850e; `commands.rs` (quarantine, settings, instance, license, exchange, line for line) in 18e850e;
   `rust/parity/cli-differential.py` (a scripted socket recording each request, both binaries on the same arguments,
   environment, stdin, folder and answers: 247 cases, 1,235 comparisons of stdout, stderr, exit status, requests and
   files, no difference; in CI) and the dispatch in main.rs in a37bb36. Found on the way and fixed: Go 1.27's
   encoding/json reads times with time.Parse (comma fractions, a one-digit hour and offsets up to 24:60 are accepted;
   the port had refused them) and names error paths differently (gojson's Ctx now follows it; the daemon differential
   still shows no difference); Go's `exchange take` panicked on a guest name the URL cannot carry (`%zz`), now an
   error. rustix 1.1.6 (RUSTSEC-2026-0486) in 20022c7. Not done here: the package branch `package-rust-daemon`
   (rebase and merge it when the daemon is switched; it is not merged, and nothing is installed).
4. The other CLI commands, one by one. Done 2026-11-11: `version`, `validate`, `plan`, `address`, an unknown command
   and no command (`cli/local.rs`, `launch.rs`; 3bf2c9d); `report` (`report.rs`, `events::read`, `parseSince` pinned
   by `cli.json`; f6e12f3); `analyze` (`cli/analyze.rs`, Content-Type in the client; 6c3e257); `seed` (`cli/seed.rs`,
   `cli/goexec.rs` for os/exec with Go's error texts, the Windows answer file in `provision.rs` pinned by
   `manifests.json`, fake ssh-keygen and xorriso in the differential; afb8a94); `image list | verify`
   (`cli/image.rs`; `image::Proofs::list` and `verify_all`; Go's ignore reasons in `load_why`; `tz.rs`, Go's local
   time zone from $TZ or /etc/localtime with its TZif reader and POSIX TZ rules, pinned by `tz.json`; the commit with
   this note). The CLI differential run: 625 cases, 3,125 comparisons, no difference (about 5 minutes: analyze polls
   every 3 s). The image cases that need root's files run under `unshare -r` (uid 0 in a user namespace, so the files
   made for the case are root's there; never real root), with `--state-dir` in the work folder and `--i-know`; a case's
   `prep` writes the record file with each image's real device, inode, size and times; 16 values of $TZ. limbo-rs gets
   `LIMBO_RS_NO_GO=1` there, so a command it does not run itself fails instead of reaching a Go limbo (without it, a
   command missing from the dispatch would be compared Go against Go: it happened to seed once). Fixed in Go on the
   way: `license.Check` and `seed` depended on map order. Next, in order, and what each needs:
   a. `doctor`, then `setup` (setup.go: what is installed, pacman, systemctl, groups): fake programs on PATH only, the
      root paths in the namespace, never the real system.
   b. `net watch`: NFLOG needs root; the daemon differential's namespace has real nft rules for it.
   c. `passthrough` (a root file, a typed "yes"), `wine` (bwrap and Wine as fakes only, never real Wine here),
      `export`, `screenshot`, `capture` (virsh, qemu-img, usbmon: fakes in the namespace), `up`, `down`, `launch` (the
      engine is ported for the daemon; launch's ssh and waypipe as fakes).
   The integration scripts call `limbo quarantine` through limbo-rs, so a ported command is exercised by the owner's
   next run of them.
