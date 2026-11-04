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

## Windows licenses

Matt's addition (2026-11-04): license key management on the same page, for programs that need more of Windows than Wine can give.

What it is for:

- Wine never needs a Windows license, because it rebuilds Windows' functions rather than running Windows.
- A program that does not work under Wine can run in a real Windows guest instead, and a Windows guest needs a license and an
  installation ISO that you supply.
- Limbo already refuses to create a Windows guest without both (`internal/license`). Today that means placing the files by hand.

What the page would do:

- **Add a license:** type the key or choose a file, and give it a name (for example "Windows 11 Pro, from my old PC").
  - It is stored root-only (`/etc/limbo/licenses/`, mode 0600).
  - Adding, removing or showing a key in full asks for the password, whatever the switch says.
  - Elsewhere it appears masked (`XXXXX-...-7K2QF`).
- **Choose the ISO** for Windows guests, which you supply. Limbo never downloads Windows.
- **Assign a license** to a Windows guest, and see which guests use which license.
- **Never:**
  - the key never goes into a log, a report or an alert;
  - it never goes to Sarina or Heimdall through their sockets;
  - it goes to a guest only while that guest's Windows installs.

Whether a key is valid stays between you and Microsoft. Limbo only checks that one was given.

Status: the Windows code in Limbo is written but has never run, so the license part is the last thing to build.

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
