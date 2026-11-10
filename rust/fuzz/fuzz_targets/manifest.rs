#![no_main]
// a manifest: parses, validates and round-trips, or is refused; the XML and rules are made without a panic
libfuzzer_sys::fuzz_target!(|data: &[u8]| limbo::fuzzing::manifest(data));
