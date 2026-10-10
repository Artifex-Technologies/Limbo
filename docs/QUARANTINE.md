# Quarantine, verdicts and validation runs

**Status: implemented and verified** with a real daemon, real sockets, real
unprivileged users, real guests and real systemd units (see
`scripts/integration-*.sh` and ARCHITECTURE.md section 12). Not verified: a real
model producing good advisories, and anything on Windows guests.

Owner's requirements (2026-10-04):

1. Heimdall may **cut a guest's network** when it sees something wrong.
2. A **human must approve** marking the quarantined item safe or dangerous.
3. **Sarina** gives an extra opinion on quarantined items.
4. Sarina may use Limbo to **validate updates and installations** (and to
   troubleshoot) before the real system is touched.

## The rule that shapes everything: restrict-only vs. loosen

An automated actor may make a guest *more* restricted. Only a human may make it
*less* restricted. This is enforced by **which socket a caller can reach**, not
by trusting the caller to behave, so a compromised Heimdall or a prompt-injected
Sarina still cannot release anything.

`limbo serve` (root) listens on three unix sockets under `/run/limbo/`:

| Socket | Mode / group | Caller | May do | May **not** do |
| --- | --- | --- | --- | --- |
| `admin.sock` | `0600` root | the human (`limbo quarantine ...`, via sudo) | everything below, plus **verdicts**, clear, destroy | — |
| `control.sock` | `0660` group `limbo-heimdall` | Heimdall | open a quarantine, raise its level, attach an advisory, list | verdicts, lowering a level, releasing, starting/stopping guests |
| `agent.sock` | `0660` group `limbo-agent` | Sarina | start validation runs, read their results, list validation profiles | touch quarantines, touch any guest not created by a run, choose a manifest |

The server records the peer's uid/pid (`SO_PEERCRED`) in the audit log for every
request. Socket permissions are the access control; the peer record is evidence.

## Quarantine lifecycle

```
            Heimdall: POST /v1/quarantine
  (none) ───────────────────────────────▶ OPEN (level = restrict | isolate)
                                            │  Heimdall may raise level, attach advisories
                       human: verdict safe  │  human: verdict dangerous
                  ┌─────────────────────────┴───────────────────────┐
                  ▼                                                 ▼
         SAFE: restrictions lifted,                    DANGEROUS: stays isolated,
         original policy re-applied                    cannot be `up`ed again; overlay
                                                       kept as evidence on teardown
                                                                    │ human: clear
                                                                    ▼
                                                                  CLOSED
```

Levels, in increasing strength (a level can only go up while OPEN):

- **restrict** — replace the guest's firewall table with the deny-all ruleset
  (the same one mode `none` uses) and keep it. The guest keeps running; the host
  can still reach it to investigate; nothing leaves it. Also repairs the case
  where the policy was missing or removed.
- **isolate** — restrict, plus take the guest's virtual link **down**
  (`virsh domif-setlink`). Independent of the firewall, so it holds even if nft
  is tampered with. The host can no longer reach the guest either.

Heimdall's automatic response is **restrict** (cheap, reversible, keeps the
guest inspectable). Going to isolate is allowed on the control socket but is
policy, not default.

A quarantined or dangerous guest **cannot be started**: `limbo up` consults the
store first.

## Advisories (Sarina's second opinion)

After Heimdall opens a quarantine it may ask Sarina for an opinion and attach the
answer to the record. An advisory is **untrusted text**: it is derived from
evidence that came out of a guest, so it can carry injected instructions. It is
capped in size, stripped of control characters, labelled with its source, shown
to the human next to the evidence, and **never changes state**. Only the human's
verdict does.

## Validation runs (Sarina validating updates)

`agent.sock` lets Sarina run a command in a **disposable** guest and read what
happened, so an update can be tried somewhere that does not matter.

- `GET /v1/profiles` returns the profile names and, as `details`, each profile's
  network mode, whether it grants sudo, and its command time cap. Read-only: it lets a
  caller plan (a profile with no sudo cannot run `pacman`) without being able to change
  anything. It also returns `skipped`, an array (empty, never null) saying why each
  profile file that exists is not offered: `{"name","code","reason","remedy"}` with
  `code` one of `profile_invalid`, `image_missing`, `image_mismatch`. `name` is empty
  unless the file name is a valid profile name; `reason` is one fixed sentence with no
  host path or raw parser text. Capped at 20 sorted by name, then a final
  `{"name":"","code":"more","reason":"N more profiles skipped","remedy":"see the Limbo log or 'limbo doctor'"}`.
  Each failure is logged once to the events log (`run.error`, `during=profile scan`).
- Sarina names a **validation profile**, not a manifest. Profiles are written by
  the human into `/etc/limbo/validation/<name>.json` (a manifest plus the ssh
  identity to use). A profile must be `disposable: true` or it is rejected.
  Sarina therefore cannot choose the network mode, the image, shares or devices.
- Each run gets a throwaway guest name, a fresh overlay and its own network, and
  is torn down when it ends, whatever the outcome.
- Timeout and output size are capped server-side.
- The result (exit status, truncated stdout/stderr, duration) is evidence for
  Sarina to reason over and for a human to approve the real update. **Sarina
  never applies the real update through this path.** A run proves the update
  behaved in the sandbox, nothing more.
- Runs are audit-logged (`run.start`, `run.end`, with a hash of the command). Every failure carries a stable code (`profile_unknown`, `boot_timeout`, `command_timeout`, ...) and a remedy hint, and a failed *command* is never an error: see `docs/INTEGRATION-FAILURES.md`.

## Sarina's advisory session has no tools

Heimdall asks Sarina's service for the advisory with `tool_allowlist: []`: the
session has **no tools at all**, and Heimdall refuses to send evidence unless the
service reports `tools: 0`. This is stricter than "no shell, no write" on
purpose. Sarina's `allow_shell` / `allow_write` flags only *deny at call time*;
the model is still offered every tool, and the first version of this integration
relied on them. The chain test, which records what Sarina's real service sends
its model, showed the advisory model was offered about 70 tools (`web_fetch`,
`memory_add`, `config_set` ...). A hostile guest could have steered it into
writing attacker text into Sarina's long-term memory. Fixed in Sarina (the
allowlist) and in Heimdall (the verification); the chain test now asserts the model
is offered `tools: []`.

## Setting up a validation profile

A profile is a manifest plus the ssh identity to use, in a directory only root can
write (`limbo serve` refuses to load profiles from anywhere else):

```
/etc/limbo/validation/arch-update.json     # see examples/validation-profile.json
/etc/limbo/keys/validation                 # private key (root-only); public key is in the manifest
```

It must have `"disposable": true`. Choose the network deliberately: `none` proves
nothing about an update that needs to download, `allowlist` with just the mirrors
is the usual choice (note that allowlist mode gives the guest no DNS, so list IP
addresses, or use `internet-only` if you accept the wider access).

Set `"access": {"user": "analyst", "sudo": true}` for a profile that vets system
updates: `pacman` needs root and runs execute as an unprivileged user, so without
`sudo` the very thing validation exists for cannot run. It is off by default and
opt-in per profile; the guest is disposable, but root inside it can reach more of the
virtual hardware than an unprivileged user, so do not enable it on guests that open
untrusted files. `max_seconds` caps the **command's** runtime; booting the guest has its
own separate budget, so a caller asking for a 10 second command does not have its guest
killed mid-boot (a real model did exactly that before this was fixed). Then, from Sarina's side:

```
sarina limbo-profiles
sarina limbo-validate arch-update pacman -Syu --noconfirm
```

The run boots a fresh guest from the profile's image, runs the command as the
profile's unprivileged user, returns exit code and (capped, untrusted) output, and
destroys the guest. If it passes, Sarina reports that to the human, who decides
about the real update.

## What this deliberately does not do

- It does not let Heimdall or Sarina release, un-quarantine, or pick a verdict.
- It does not trust Sarina's text. A hostile guest that can influence what
  Sarina reads can influence what Sarina *says*; the design assumes it will.
- It does not claim a validation run predicts the real system. It uses whatever
  image the profile points at; fidelity to the host is the human's choice.
