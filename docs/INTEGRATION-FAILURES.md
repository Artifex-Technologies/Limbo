# Sarina integration: failure runbook

For an operator, or for Sarina's agent reading a tool result. Companion to
`docs/QUARANTINE.md` (which owns the `agent.sock` contract).

## The one rule: a failed command is not a failed run

A validation run ends one of three ways, and they must never be confused:

| What the result says | Meaning | A model should |
| --- | --- | --- |
| `status: done`, an `exit_code` (zero **or not**), no `code` | The command ran in the guest. A non-zero exit is the *answer* ("the update fails in the sandbox"). | Reason about the output. |
| `status: failed`, an `error` starting `<code>:`, **no** `exit_code` | Limbo could not run the command (infrastructure). The command's outcome is **unknown**, not "failed". | Report the problem and the remedy. Never conclude the update is bad or good. |
| `status: timeout`, `command_timeout` | The command ran past its limit and was killed. Output so far is returned. | Treat as "did not finish", not as pass or fail. |

Two informational codes ride on a normal `done` result: `output_truncated` and
`teardown_failed`. They mean "the command ran, with a caveat".

## What an error looks like on the wire

Every failure on `agent.sock` carries, in JSON:

```
{"error": "<code>: <message>. Remedy: <hint>", "code": "<code>", "message": "...", "remedy": "..."}
```

`error` is one self-contained line, because Sarina's client shows only that
field. Run results (`GET /v1/runs/{id}`) carry the same text in `error`, plus
`code` and `remedy` fields. Messages never contain host paths (only the profile
name or run id), secrets, or raw output of libvirt/QEMU/ssh. The raw detail goes
to the journal, not to the model.

Every failure is also written to the events log
(`/var/lib/limbo/state/events.jsonl`) as `run.error` with `detail.code` equal to
the code above; `run.end` repeats it in `detail.code`.

## Failure table

| Failure | Code | Symptom (what Sarina shows) | How Limbo detects it | Remedy |
| --- | --- | --- | --- | --- |
| `limbo serve` not running | none (client side) | `could not reach Limbo at ...: connect: connection refused` or `no such file or directory` | Sarina's dial fails | Section A below |
| `limbo serve` restarted mid-run | `run_unknown` on the next poll | `run_unknown: there is no run with that id` | Run records are in memory; startup reaps the dead run's guest (`run.error` with `during=startup reap`) | Start the run again. The old guest is already destroyed |
| Socket missing / wrong group or mode | none (client side) | `permission denied` or `no such file or directory` on the socket | Sarina's dial fails | Section A below |
| Request body malformed, unknown field, or over 64 KiB | `bad_request` | `bad_request: the request body ...` (HTTP 400) | JSON decode with unknown fields refused; body capped | Send exactly `profile`, `command`, `timeout_seconds` |
| Empty command, over 4096 bytes, or NUL byte | `bad_request` | `bad_request: command must be 1-4096 bytes` | `runs.Start` | Shorten the command; put long scripts on a host the guest can read |
| Profile name not `^[a-z][a-z0-9-]{0,31}$` (includes `../` traversal) | `profile_invalid` | `profile names are lowercase letters, digits and hyphens` | Name check runs before any file is opened | Use a name from `limbo_profiles` |
| Profile does not exist | `profile_unknown` | `there is no profile named "x"` | No file in the profile directory | `limbo_profiles`; operator adds the file |
| Profile file malformed, unknown field, not `disposable`, not Linux, relative `ssh_identity`, bad manifest | `profile_invalid` | `profile "x" is malformed (...)` / `is not disposable` | `loadProfile` | Operator fixes the file; `limbo validate` checks a manifest. An invalid profile is absent from `profiles` but listed in `skipped` with this code |
| Base image missing | `image_missing` (at start, before anything is created) | `the base image for profile "x" is missing` | `stat` of the image path | Restore the image at the path in the profile |
| Profile asks for a host device (`devices.pci`) and this host will not give it (Chymaera OS, unknown OS, device not in `host-policy.json`, boot display, shared IOMMU group) | `hardware_denied` | `the profile needs a host device and this host does not allow it` | `hostpolicy.Check` in `Engine.Up` and at run start; the specific reason is in the `gate.blocked` event, never shown to the caller | Operator: use a profile without devices, or fix `/etc/limbo/host-policy.json` on a Labyrinth host |
| Device is allowed here but no person approved a GPU test window (or it expired) | `approval_required` | `the profile needs a real host device and the user has not approved a GPU test window` | `hostpolicy.Ready` at run start and in `Engine.Up` | Sarina asks the user, who runs `sudo limbo passthrough approve ADDR` at a terminal |
| Host software is using the device | `hardware_busy` | `the device is in use on the host` | `/proc` scan; the process names are in the `gate.blocked` event | User closes the apps (and moves the desktop off that GPU), then retry |
| An earlier run left the device unusable | `reboot_required` | `a passthrough device did not return to the host cleanly` | `hardware.stuck` event, marker in `/run/limbo` | Reboot the host (clears itself), or `limbo passthrough clear` after recovering the device |
| Image checksum differs from the profile's `sha256` | `image_mismatch` | `the profile's base image does not match its recorded checksum` | `image.Verify` before define; also logs `image.rejected` | Re-verify the image; update `sha256` only if the change is intended |
| libvirt/QEMU/nft/xorriso/ssh missing or libvirtd down | `virt_unavailable` | `the virtualization stack is unavailable on the host` | Executable not found, or "failed to connect to the hypervisor" | `limbo doctor`; `systemctl status libvirtd virtqemud` |
| Guest will not start, or never answers ssh | `boot_failed` | `the guest could not be started or never became reachable` | Error from `virsh start` / seed build | Retry once; `journalctl -u limbo`; `virsh -c qemu:///system list --all` |
| Boot slower than the budget (300 s total, 180 s waiting for ssh) | `boot_timeout` | `the guest did not become ready within its boot budget` | Boot context deadline; the command's own clock has not started | Retry; check host load (`uptime`) and that KVM is used (`ls -l /dev/kvm`) |
| Command exceeds its limit (requested timeout clamped to 10-900 s by Sarina and to the profile's `max_seconds` by Limbo) | `command_timeout`, `status: timeout` | `the command was still running after N seconds and was killed` | Command context deadline | Raise `timeout_seconds` up to the profile limit, or run less |
| Guest killed or powered off mid-command | `guest_killed` | `the guest stopped responding while the command was running` | ssh exits 255 (connection lost) during the command | Retry; a repeat means the command crashes the guest (OOM, `poweroff`) |
| Host out of disk or memory | `host_resources` | `the host ran out of disk space or memory` | Error text from qemu-img/virsh/event-log write | `df -h /var/lib/limbo`; `free -m`; free space, retry |
| Two runs at once | `busy` (HTTP 429) once 2 are running | `2 validation runs are already in progress` | Concurrency cap | Wait a minute, retry. Runs are isolated from each other |
| Huge or binary output | `output_truncated` on a `done` result | `(output was truncated)`; stdout/stderr cut at the profile's cap (64 KiB default) | Capped at read; control characters stripped, invalid UTF-8 replaced | Filter in the command (`tail`, `grep`) and rerun |
| Command's own ssh-like failure other than the above | `run_failed` | `Limbo could not run the command in the guest (this is not the command failing)` | Executor error that is not a connection loss | Retry; read `journalctl -u limbo` |
| Teardown did not finish | `teardown_failed` on a `done` result | `the command ran but cleaning up the guest did not finish` | `Down` returned an error; the run's state directory is kept as a marker | The next `limbo serve` start retries it; or destroy by hand (below) |
| Client disconnects mid-run | none | nothing; the run continues, is torn down, and its result stays readable for the last 50 runs | The run uses a context detached from the request | Poll `GET /v1/runs/{id}` |
| Unknown or expired run id | `run_unknown` | `there is no run with that id` | Not in the in-memory table | Start again |

Failure inside `limbo serve` itself, before any request (not root, missing
tools, profile directory writable by non-root) stops the unit; the reason is in
`journalctl -u limbo`.

## A. Diagnosing "could not reach Limbo"

Run these on the host, in order, and stop at the first that fails.

```sh
systemctl status limbo                          # is the unit active? (unit name: limbo.service)
journalctl -u limbo -n 50 --no-pager            # why it stopped or restarts (Restart=on-failure, RestartSec=2)
ls -l /run/limbo/                               # agent.sock must exist: srw-rw---- root limbo-agent
id sarina                                       # the account Sarina runs as must list limbo-agent
echo $SARINA_LIMBO_SOCKET                       # must be /run/limbo/agent.sock (Sarina refuses any other file name)
curl --unix-socket /run/limbo/agent.sock http://limbo/v1/profiles   # run AS Sarina's user (sudo -u sarina ...)
```

| What you see | Cause | Fix |
| --- | --- | --- |
| `/run/limbo/` empty or missing | `limbo serve` not running | `sudo systemctl start limbo`; read the journal if it exits |
| Socket exists, `Permission denied` for Sarina's user | not in `limbo-agent`, or the group was added after Sarina started | `sudo usermod -aG limbo-agent <user>` then restart Sarina's service (group changes need a new login/process) |
| Socket mode not `0660` or group not `limbo-agent` | `limbo serve` was started with different `--agent-group` | Restart with the packaged unit |
| `connection refused` with the socket present | stale socket from a crashed process | `sudo systemctl restart limbo` (it recreates the sockets) |
| `{"profiles":[],"details":[],"skipped":[...]}` | no valid profile; `skipped` says why for each file (`limbo doctor` lists them too) | `ls -l /etc/limbo/validation/`; each file must be valid and `"disposable": true` (a directory that is not root-owned, or is group/world-writable, stops `limbo serve` instead: see the journal) |
| Sarina says `refusing to use ... never to its admin or control sockets` | `SARINA_LIMBO_SOCKET` points at another socket | Set it to `/run/limbo/agent.sock` |

## B. Diagnosing a failed run

```sh
# What did Limbo log for it? (id is in Sarina's result, e.g. r1a2b3c4d)
grep '"run.error"' /var/lib/limbo/state/events.jsonl | tail -5
grep r1a2b3c4d /var/lib/limbo/state/events.jsonl

# Ask the socket directly (as Sarina's user)
curl --unix-socket /run/limbo/agent.sock http://limbo/v1/runs/r1a2b3c4d

# Host health behind boot_failed / boot_timeout / host_resources / virt_unavailable
sudo limbo doctor
systemctl status libvirtd virtqemud virtnetworkd
ls -l /dev/kvm
df -h /var/lib/limbo
free -m
```

Leftover guests (should be none; the next `limbo serve` start reaps them):

```sh
sudo virsh -c qemu:///system list --all | grep limbo-r      # leftover run guests
sudo virsh -c qemu:///system destroy limbo-r1a2b3c4d
sudo virsh -c qemu:///system undefine limbo-r1a2b3c4d
sudo virsh -c qemu:///system net-destroy limbo-r1a2b3c4d; sudo virsh -c qemu:///system net-undefine limbo-r1a2b3c4d
sudo nft delete table inet limbo_r1a2b3c4d
sudo rm -rf /var/lib/limbo/state/runs/r1a2b3c4d             # last, after the guest is gone
```

## Known gaps

- A profile that exists but is invalid is reported in `GET /v1/profiles` under
  `skipped` (`{name, code, reason, remedy}`: `profile_invalid`, `image_missing`,
  `image_mismatch`; at most 20, then a `more` entry), logged once to the events
  log, and listed by `limbo doctor`. The reason is a fixed sentence: for the
  parser text or the path, read the profile file and `limbo validate`. A profile
  whose image is missing or altered is listed only under `skipped`, not `profiles`.
- A command that itself exits 255 is indistinguishable from an ssh failure and
  is reported as `guest_killed` or `run_failed`.
- Run records live in memory only; after a restart a finished run's result is
  gone (`run_unknown`). The audit log is the durable record.
- Verified with fakes (unit tests) and by reading the code; not exercised against
  a real guest killed mid-command or a full disk.
