use libc::{c_char, c_void};

#[repr(C)]
/// Opaque solver ctx struct
pub struct SolverCtx { _unused : [ u8 ; 0 ] }

extern {
    fn new_solver_ctx() -> *const SolverCtx;
    fn delete_solver_ctx(ctx: *const SolverCtx) -> c_void;
    fn stop_miner(ctx: *const SolverCtx);

    fn start_miner(
        ctx: *const SolverCtx,
        header: *const c_char, 
        nonce: *mut u64, 
        proof: *mut u64, 
        proofsize: u64, 
        range: u64
    ) -> c_void;
    
    fn verify(
        header: *const c_char, 
        nonce: u64, 
        proof: *const u64, 
        proof_size: u64
    ) -> bool;

    fn found_solution(ctx: *const SolverCtx) -> i32;
}