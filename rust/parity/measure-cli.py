#!/usr/bin/env python3
"""The Go limbo of the pinned commit (rust/parity/go-limbo.sh) against the Rust one, on commands that need no daemon and
no root: wall time, CPU (user + system) and peak RSS, the median of --runs runs each with p10-p90, after one unmeasured
run of each. Old and new run one after the other, alternating which goes first, one process at a time, at nice 19.

A small C launcher (built here with cc) starts each program and reports from wait4: started from Python directly, a
program's peak would count Python's own memory before exec. Output goes to /dev/null; the outputs were compared once by
hand (identical). Prints a Markdown table.

    python3 -I rust/parity/measure-cli.py --go /tmp/limbo-go --rs rust/target/release/limbo-rs
"""
import argparse
import os
import statistics
import subprocess
import sys
import tempfile

LAUNCHER = r"""
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct timespec a, b;
    struct rusage ru;
    int st;
    if (argc < 2) return 2;
    clock_gettime(CLOCK_MONOTONIC, &a);
    pid_t p = fork();
    if (p == 0) {
        int fd = open("/dev/null", O_WRONLY);
        dup2(fd, 1);
        dup2(fd, 2);
        execv(argv[1], argv + 1);
        _exit(127);
    }
    wait4(p, &st, 0, &ru);
    clock_gettime(CLOCK_MONOTONIC, &b);
    printf("%.6f %.6f %ld %d\n", (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9,
           ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 + ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6,
           ru.ru_maxrss, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return 0;
}
"""


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, round(q * (len(xs) - 1))))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", required=True)
    ap.add_argument("--rs", required=True)
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--manifest", default="examples/analysis-linux.json")
    a = ap.parse_args()
    os.nice(19)
    tmp = tempfile.mkdtemp(prefix="limbo-measure-")
    src, exe = os.path.join(tmp, "launch.c"), os.path.join(tmp, "launch")
    with open(src, "w") as f:
        f.write(LAUNCHER)
    subprocess.run(["cc", "-O2", "-o", exe, src], check=True)
    cases = [
        ("no arguments (the usage)", []),
        ("`validate` a manifest", ["validate", a.manifest]),
        ("`plan` a manifest (domain XML, firewall rules)", ["plan", a.manifest]),
        ("`doctor` (starts the tools it checks)", ["doctor"]),
    ]

    def once(binary, args):
        out = subprocess.run([exe, os.path.abspath(binary)] + args, capture_output=True, text=True, check=True).stdout.split()
        # ru_maxrss is in KiB; MB here are 10^6 bytes, as the daemon's figures
        return float(out[0]) * 1000, float(out[1]) * 1000, int(out[2]) * 1024 / 1e6, int(out[3])

    floor = [once("/usr/bin/true", []) for _ in range(a.runs)]
    print("| Command | Go: wall | Rust: wall | Change | Go: CPU | Rust: CPU | Go: peak RSS | Rust: peak RSS |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for name, args in cases:
        got = {"go": [], "rs": []}
        once(a.go, args), once(a.rs, args)
        for i in range(a.runs):
            order = [("go", a.go), ("rs", a.rs)] if i % 2 == 0 else [("rs", a.rs), ("go", a.go)]
            for k, b in order:
                got[k].append(once(b, args))
        codes = {k: {r[3] for r in v} for k, v in got.items()}
        if codes["go"] != codes["rs"]:
            print("exit codes differ for %s: %s" % (name, codes), file=sys.stderr)
        med = {k: [statistics.median(r[j] for r in v) for j in range(3)] for k, v in got.items()}
        span = {k: (pct([r[0] for r in v], 0.1), pct([r[0] for r in v], 0.9)) for k, v in got.items()}
        change = (med["go"][0] - med["rs"][0]) / med["go"][0] * 100
        print("| %s | %.2f ms (%.2f-%.2f) | %.2f ms (%.2f-%.2f) | %+.0f %% | %.2f ms | %.2f ms | %.1f MB | %.1f MB |" % (
            name, med["go"][0], *span["go"], med["rs"][0], *span["rs"], -change, med["go"][1], med["rs"][1],
            med["go"][2], med["rs"][2]))
    print()
    print("Floor (`/usr/bin/true` through the launcher): %.2f ms, %.1f MB." % (
        statistics.median(r[0] for r in floor), statistics.median(r[2] for r in floor)))


if __name__ == "__main__":
    main()
