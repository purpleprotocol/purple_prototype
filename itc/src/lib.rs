extern crate libc;
use libc::c_char;

#[repr(C)]
pub struct Stamp;

extern "C" {
    fn newStamp() -> Stamp;
    fn itc_seed() -> Stamp;
    fn itc_fork(s: Stamp, rl: Stamp, rr: Stamp) -> i32;
    fn itc_join(s1: Stamp, s2: Stamp, sr: Stamp) -> i32;
    fn itc_event(in_s: Stamp, out_s: Stamp) -> i32;
    fn itc_peek(in_s: Stamp, out_s: Stamp) -> i32;
    fn itc_leq(s1: Stamp, s2: Stamp) -> c_char;
}

pub fn new() -> Stamp {
    unsafe { newStamp() }
}

pub fn seed() -> Stamp {
    unsafe { itc_seed() }
}

pub fn fork(stamp: Stamp, rl: Stamp, rr: Stamp) -> Result<&'static str, &'static str> {
    let result = unsafe { itc_fork(stamp, rl, rr) };

    match result {
        -1 => Err("Bad stamp"),
        1  => Ok(""),
        _  => panic!()
    }
}

pub fn join(stamp1: Stamp, stamp2: Stamp, result: Stamp) -> Result<&'static str, &'static str> {
    let result = unsafe { itc_join(stamp1, stamp2, result) };

    match result {
        -1 => Err("Bad stamp"),
        1  => Ok(""),
        _  => panic!()
    }
}

pub fn event(in_stamp: Stamp, out_stamp: Stamp) -> Result<&'static str, &'static str> {
    let result = unsafe { itc_event(in_stamp, out_stamp) };

    match result {
        -1 => Err("Bad stamp"),
        1  => Ok(""),
        _  => panic!()
    }
}

pub fn peek(in_stamp: Stamp, out_stamp: Stamp) -> Result<&'static str, &'static str> {
    let result = unsafe { itc_peek(in_stamp, out_stamp) };

    match result {
        -1 => Err("Bad stamp"),
        1  => Ok(""),
        _  => panic!()
    }
}

pub fn leq(stamp1: Stamp, stamp2: Stamp) -> bool {
    let result = unsafe { itc_leq(stamp1, stamp2) };

    match result {
        0 => false,
        1 => true,
        _ => panic!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_compares_stamps() {
        let seed_stamp = seed();
        let r = new();
        let l = new();
        let r1 = new();
        
        // Fork seed stamp
        fork(seed_stamp, r, l);

        // Increment event
        event(r, r1);

        assert!(leq(r, r1));    
    }
}
