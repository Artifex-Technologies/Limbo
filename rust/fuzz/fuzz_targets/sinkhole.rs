#![no_main]
// what a guest in network mode sinkhole sends, and a line from its responder
libfuzzer_sys::fuzz_target!(|data: &[u8]| limbo::fuzzing::sinkhole(data));
