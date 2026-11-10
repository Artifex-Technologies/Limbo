#![no_main]
// JSON as Go reads it (requests, manifests, state files)
libfuzzer_sys::fuzz_target!(|data: &[u8]| limbo::fuzzing::json(data));
