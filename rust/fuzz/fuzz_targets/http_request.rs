#![no_main]
// any bytes on any socket: no panic, and control.sock and agent.sock reach only their own routes
libfuzzer_sys::fuzz_target!(|data: &[u8]| limbo::fuzzing::http_request(data));
