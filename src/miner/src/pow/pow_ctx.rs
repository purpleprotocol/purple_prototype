use crate::pow::proof::Proof;
use crate::pow::error::Error;
use crate::pow::common::EdgeType;

/// Generic trait for a solver/verifier providing common interface into Cuckoo-family PoW
/// Mostly used for verification, but also for test mining if necessary
pub trait PoWContext<T>
where
    T: EdgeType,
{
    /// Sets the header along with an optional nonce at the end
    /// solve: whether to set up structures for a solve (true) or just validate (false)
    fn set_header_nonce(
        &mut self,
        header: Vec<u8>,
        nonce: Option<u32>,
        solve: bool,
    ) -> Result<(), Error>;
    /// find solutions using the stored parameters and header
    fn find_cycles(&mut self) -> Result<Vec<Proof>, Error>;
    /// Verify a solution with the stored parameters
    fn verify(&self, proof: &Proof) -> Result<(), Error>;
}