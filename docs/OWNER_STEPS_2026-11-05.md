# Owner steps, 2026-11-05 (Limbo)

What Limbo's work today needs from me, as exact commands. Nothing here was run for me. Another session merges these into
`~/Desktop/finish-todo.sh`. Run them **after 04:20** (Sarina's night run uses Limbo from 22:30) or on a day off.

## 1. Install the new Limbo and restart it (needed for everything below)

Done since: `limbo-git` r38 is installed and `/run/limbo/user.sock` is up.

Today's work is committed and pushed but not installed: the PC still runs `limbo-git` r16, so `user.sock`, the Settings page
routes, the guest network events and the other fixes are not live yet.

```bash
cd ~/Documents/Github/Labyrinth_OS/packages/pkgbuilds/limbo-git
makepkg -f                                   # as myself, not root: builds from the local Limbo checkout and runs its tests
sudo pacman -U ./limbo-git-0.1.0.r*.pkg.tar.zst   # pick the newest file; pacman's sysusers hook creates the group limbo-users
sudo systemctl restart limbo                 # the new daemon: user.sock appears, guest network events start
systemctl is-active limbo && ls -l /run/limbo/
```

Check: `/run/limbo/user.sock` exists, mode `srw-rw----`, group `limbo-users`. If it is missing, `journalctl -u limbo -n 20` says
why (usually: the group does not exist; then `sudo limbo setup` creates it).

What changes for things already in use: guests now boot from an overlay even when persistent (none are on this PC; validation runs
were already disposable); guest subnets are allocated instead of hashed (runs are unaffected); the firewall logs refusals to group
7213 (nothing else on this PC uses that group).

## 2. Let your account read Limbo's figures without a password

```bash
sudo gpasswd -a "$USER" limbo-users          # then log out and in again (group membership is read at login)
limbo settings show                          # should print the status and the instances table, without sudo
```

With the switch on (the default) this only lets you **read**. To let your account start and stop its own guests and change them
without the password (as approved on 2026-11-04):

```bash
sudo limbo settings password off             # "Ask for my password for Limbo changes": off
sudo limbo settings password on              # back to how it was
```

Verdicts, loosening a guest Heimdall holds, the switch itself, licenses' keys and group membership still always need the password.

## 3. Optional: shared folders a guest can write to

A guest's writable shared folder is now only ever its own outbox, `/var/lib/limbo/exchange/<name>`, and files leave it only through
`limbo exchange take` after ClamAV scans them. Limbo still refuses a writable share unless the folder's mount forbids setuid programs
and device nodes. `/var/lib/limbo` is on the root filesystem here, which allows both, so a writable share would be refused today. To
allow it, give the exchange folder its own nosuid,nodev,noexec bind mount:

```bash
sudo install -d -m 0700 /var/lib/limbo/exchange
echo '/var/lib/limbo/exchange /var/lib/limbo/exchange none bind,nosuid,nodev,noexec 0 0' | sudo tee -a /etc/fstab
sudo systemctl daemon-reload && sudo mount /var/lib/limbo/exchange
findmnt /var/lib/limbo/exchange             # OPTIONS should include nosuid,nodev,noexec
```

Skip this if you do not need guests to hand files back; read-only shares need nothing.

ClamAV: Limbo uses `clamdscan` when the clamd service runs and `clamscan` otherwise. `clamscan` loads the virus database for each
file taken out (several seconds and about 1 GiB of memory while it runs), but costs nothing when idle; clamd is faster but keeps
about 1 GiB in memory all the time. Recommendation: leave clamd off (Yggdrasil must stay light); nothing to run.

## 4. Optional: register a guest you keep (an "instance")

Instances are the rows the Settings page can start and stop. None exist yet. When you want one: write a manifest
(`/usr/share/doc/limbo-git/examples/analysis-linux.json` is a start; `"disposable": false`), then

```bash
limbo seed --iso ~/limbo-seeds/NAME.iso MANIFEST ~/limbo-seeds/NAME   # also makes the guest's SSH host key and prints the
                                                                      # "host_key" line to add to the manifest (launch needs it)
sudo limbo instance add MANIFEST                                      # owner defaults to you
```

## 5. Windows licenses (when you have one)

Nothing to do until then. When you do: `sudo limbo license add --name "Windows 11 Pro, old PC"` and type the key (it is read from
the keyboard, never from the command line). Limbo stores it root-only and shows it masked. The Windows installation itself is still
not built (no ISO or license has been available to build it against).
