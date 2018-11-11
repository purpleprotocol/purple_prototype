pub trait Hashable {
    fn hash_self(&mut self) -> ();
}

pub trait Signable {
    fn sign(&mut self) -> ();
}