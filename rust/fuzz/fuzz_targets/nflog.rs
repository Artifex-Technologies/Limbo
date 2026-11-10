#![no_main]
// a netlink read from the NFLOG group
libfuzzer_sys::fuzz_target!(|data: &[u8]| limbo::fuzzing::nflog(data));
