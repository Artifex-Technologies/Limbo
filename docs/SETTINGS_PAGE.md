# Limbo in Settings (proposal, 2026-11-04)

Matt's idea (2026-11-04): a Limbo page in Yggdrasil's Settings where the person using the computer decides whether Limbo changes ask
for their password, plus figures such as how much space each instance uses. Nothing here is built yet.

## Today

- Sarina uses Limbo through `agent.sock` (group `limbo-agent`) and Heimdall through `control.sock` (group `limbo-heimdall`). Neither
  needs a password, and this proposal does not change that.
- Everything a person does (`up`, `down`, `analyze`, quarantine verdicts) goes through `admin.sock`, which only root can use, so
  every change needs sudo.

## The page

Settings > Security > Limbo (next to Heimdall):

1. **Status:** whether Limbo is installed and running, whether KVM is available, and the total space Limbo uses.
2. **Instances:** one row per guest, showing:
   - its name and system (Linux or Windows);
   - its state (running, stopped or held by quarantine);
   - its disk use (base image plus the guest's own changes);
   - the memory and processors it is given, and whether it has network.

   Start and Stop buttons, and "Free space" for a stopped guest's changes.
3. **Quarantine:** what is held and why, with Sarina's advisory clearly labelled as untrusted, and the Safe / Dangerous verdict.
4. **Ask for my password for Limbo changes:** on by default, which is how Limbo works today. Turning it off or back on always
   asks for the password (pkexec).

## What the switch covers

With the switch **off**, members of a new group `limbo-users` may, through a new `user.sock`:

- start and stop their guests;
- change a guest's processors, memory and disk size;
- change a guest's shared folders, clipboard and devices.

**Always behind the password, whatever the switch says** (recommended):

- quarantine verdicts, and anything that loosens a guest Heimdall restricted (its network, its devices);
- the switch itself;
- adding or removing a person or service from `limbo-users`, `limbo-agent` or `limbo-heimdall`.

The reason: any program running as you can use a socket you can use, including a hostile one. If verdicts did not need the
password, malware in a browser could declare its own sample safe or free a guest Heimdall locked.

## Figures without a password

The page shows figures (instances, states, disk use, memory) even with the switch on. They come through read-only routes on
`user.sock` (GET only), so looking never needs sudo.

## Later, if wanted

Possible additions:

- per-guest network rules (which hosts a guest may reach);
- snapshots ("go back to how it was yesterday");
- a default memory and processor limit for new guests;
- the audit log in plain words;
- a one-click `limbo report`.

## Open question for Matt

Should quarantine verdicts and loosening a restricted guest stay behind the password even when the switch is off? This is
recommended. The alternative is to let the switch cover everything.
