//! Candidate ATT&CK techniques for a sample run (LIM-7): names of a few system calls, Windows API functions and registry
//! keys that a triage listing (imports, strings) shows, each with the technique it is typical of. They are suggestions only:
//! a name in the output says the file mentions it, not that it uses it, and the output is untrusted (a hostile file can
//! plant any name, so at worst it adds suggestions). What is printed or logged is this table's own text, never the
//! output's. The IDs are in Heimdall's technique table (ATT&CK Enterprise 20.1, its internal/attack/enterprise.tsv).
//!
//! Left out on purpose: names nearly every Windows program imports (IsDebuggerPresent comes with the C runtime,
//! LoadLibrary and GetProcAddress with almost anything), which would suggest techniques for every file.

use std::collections::BTreeMap;

/// (name as an import list or a string shows it, technique ID, technique name). A name with a backslash is a registry key,
/// found anywhere and in any case; the others are found as whole names (`ptrace@GLIBC_2.2.5` counts, `myptrace` does not).
const NAMES: &[(&str, &str, &str)] = &[
    ("ptrace", "T1055.008", "Process Injection: Ptrace System Calls"),
    ("process_vm_writev", "T1055", "Process Injection"),
    ("CreateRemoteThread", "T1055", "Process Injection"),
    ("CreateRemoteThreadEx", "T1055", "Process Injection"),
    ("NtCreateThreadEx", "T1055", "Process Injection"),
    ("RtlCreateUserThread", "T1055", "Process Injection"),
    ("VirtualAllocEx", "T1055", "Process Injection"),
    ("WriteProcessMemory", "T1055", "Process Injection"),
    ("SetThreadContext", "T1055.003", "Process Injection: Thread Execution Hijacking"),
    ("QueueUserAPC", "T1055.004", "Process Injection: Asynchronous Procedure Call"),
    ("NtQueueApcThread", "T1055.004", "Process Injection: Asynchronous Procedure Call"),
    ("NtUnmapViewOfSection", "T1055.012", "Process Injection: Process Hollowing"),
    ("ZwUnmapViewOfSection", "T1055.012", "Process Injection: Process Hollowing"),
    ("SetWindowsHookExA", "T1056.001", "Input Capture: Keylogging"),
    ("SetWindowsHookExW", "T1056.001", "Input Capture: Keylogging"),
    ("GetAsyncKeyState", "T1056.001", "Input Capture: Keylogging"),
    ("CheckRemoteDebuggerPresent", "T1622", "Debugger Evasion"),
    ("RegSetValueExA", "T1112", "Modify Registry"),
    ("RegSetValueExW", "T1112", "Modify Registry"),
    ("CurrentVersion\\Run", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
    ("URLDownloadToFileA", "T1105", "Ingress Tool Transfer"),
    ("URLDownloadToFileW", "T1105", "Ingress Tool Transfer"),
    ("AdjustTokenPrivileges", "T1134", "Access Token Manipulation"),
    ("MiniDumpWriteDump", "T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("memfd_create", "T1620", "Reflective Code Loading"),
    ("LD_PRELOAD", "T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking"),
];

/// One suggested technique and the table's names that were seen for it.
#[derive(Debug, PartialEq)]
pub struct Suggestion {
    pub id: &'static str,
    pub name: &'static str,
    pub seen: Vec<&'static str>,
}

fn word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn seen(text: &[u8], name: &str) -> bool {
    let n = name.as_bytes();
    if name.contains('\\') {
        return text.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n));
    }
    let mut from = 0;
    while let Some(i) = text[from..].windows(n.len()).position(|w| w == n) {
        let at = from + i;
        let before = at.checked_sub(1).map(|j| text[j]);
        let after = text.get(at + n.len()).copied();
        if !before.is_some_and(word_char) && !after.is_some_and(word_char) {
            return true;
        }
        from = at + 1;
    }
    false
}

/// The techniques whose names appear in `text`, by ID.
pub fn suggest(text: &str) -> Vec<Suggestion> {
    let mut by_id: BTreeMap<&str, Suggestion> = BTreeMap::new();
    for &(name, id, tname) in NAMES {
        if seen(text.as_bytes(), name) {
            by_id.entry(id).or_insert_with(|| Suggestion { id, name: tname, seen: vec![] }).seen.push(name);
        }
    }
    by_id.into_values().collect()
}

/// The IDs for an event's detail: "T1055,T1055.008"; empty when none.
pub fn ids(text: &str) -> String {
    suggest(text).iter().map(|s| s.id).collect::<Vec<_>>().join(",")
}

/// What `limbo analyze` prints after a run's output: a heading and a line per technique; nothing when none.
pub fn text(output: &str) -> String {
    let found = suggest(output);
    if found.is_empty() {
        return String::new();
    }
    let mut t = String::from(if output.is_empty() || output.ends_with('\n') { "\n" } else { "\n\n" });
    t.push_str(
        "== suggested ATT&CK techniques (names in the output above are typical of them; not verified, and the output is untrusted)\n",
    );
    for s in found {
        t.push_str(&format!("suggested: {} {} (seen: {})\n", s.id, s.name, s.seen.join(", ")));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_names_only_and_registry_keys_in_any_case() {
        let ids_of = |t: &str| suggest(t).iter().map(|s| s.id).collect::<Vec<_>>();
        // as objdump, readelf and a PE import list show them
        assert_eq!(ids_of("  0x0 FUNC GLOBAL ptrace@GLIBC_2.2.5\n"), ["T1055.008"]);
        assert_eq!(ids_of("KERNEL32.dll!CreateRemoteThread\nKERNEL32.dll!WriteProcessMemory"), ["T1055"]);
        assert_eq!(ids_of("SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE"), ["T1547.001"]);
        // inside a longer name: not that name
        assert!(suggest("myptrace_wrapper NotCreateRemoteThreadAtAll ptrace2").is_empty());
        // the Ex form is its own entry, the plain one is not seen in it
        let s = suggest("CreateRemoteThreadEx");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].seen, ["CreateRemoteThreadEx"]);
        // in ID order, each name once
        assert_eq!(ids("ptrace ptrace CreateRemoteThread MiniDumpWriteDump"), "T1003.001,T1055,T1055.008");
        assert_eq!(ids("PE32 executable (GUI) Intel 80386"), "");
    }

    #[test]
    fn the_printed_block_is_the_tables_text_only() {
        // a planted line around a name: only the table's words come out
        let out = "== imports\nKERNEL32.dll!CreateRemoteThread\u{1b}[31m<script>\n";
        let t = text(out);
        assert_eq!(
            t,
            "\n== suggested ATT&CK techniques (names in the output above are typical of them; not verified, and the output is \
             untrusted)\nsuggested: T1055 Process Injection (seen: CreateRemoteThread)\n"
        );
        assert!(!t.contains("script") && !t.contains('\u{1b}'));
        assert!(text("ends without a newline ptrace").starts_with("\n\n== suggested"));
        assert_eq!(text("nothing to suggest\n"), "");
        // every ID in the table is a technique ID, every name is plain text
        for (name, id, tname) in NAMES {
            assert!(id.starts_with('T') && id[1..].chars().all(|c| c.is_ascii_digit() || c == '.'), "{id}");
            assert!(!name.is_empty() && !tname.is_empty() && tname.is_ascii());
        }
    }
}
