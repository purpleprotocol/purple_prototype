use libc::{c_char, c_void};
use std::ffi::CString;

#[repr(C)]
/// Opaque solver ctx struct
pub struct SolverCtx { _unused : [ u8 ; 0 ] }

extern {
    fn new_solver_ctx(
        nthreads: u32, 
        ntrims: u32, 
        showcycle: bool, 
        allrounds: bool
    ) -> *const SolverCtx;

    fn delete_solver_ctx(ctx: *const SolverCtx) -> c_void;
    fn stop_miner(ctx: *const SolverCtx);

    fn start_miner(
        ctx: *const SolverCtx,
        header: *const c_char, 
        nonce: u64, 
        proof: *mut u64, 
        proofsize: u32
    ) -> c_void;
    
    fn verify_proof(
        header: *const c_char, 
        nonce: u64, 
        proof: *const u64, 
        proof_size: u32
    ) -> bool;

    fn found_solution(ctx: *const SolverCtx) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_succesfuly_finds_proof() {
        let header = CString::new("test_header").unwrap();
        const PROOFSIZE: usize = 6;
        let mut nonce = 0;
        let mut proof: Vec<u64> = Vec::new();

        unsafe {
            println!("DEBUG 1");
            let ctx = new_solver_ctx(4, 0, false, false);
            println!("DEBUG 2");
            start_miner(ctx, header.as_ptr(), nonce, proof.as_mut_ptr(), PROOFSIZE as u32);
            println!("DEBUG 3");
            assert!(verify_proof(header.as_ptr(), nonce, proof.as_ptr(), PROOFSIZE as u32));
            println!("DEBUG 4");
            delete_solver_ctx(ctx);
            println!("DEBUG 5");
        }
    }
}