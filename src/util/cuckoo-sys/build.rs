#[cfg(not(test))]
const EDGE_BITS: usize = 29;

#[cfg(test)]
const EDGE_BITS: usize = 12;

#[cfg(not(feature = "gpu"))]
fn main() {
    cc::Build::new()
        .cpp(true)
        .flag("-std=c++11")
        // .flag("-mavx2") // Uncomment for AVX2
        // .flag("-DNSIPHASH=8")
        .flag("-DNSIPHASH=1")
        .flag(&format!("-DEDGEBITS={}", EDGE_BITS))
        .flag("-Wno-deprecated")
        .flag("-Wno-unused-parameter")
        .file("c_src/crypto/blake2b-ref.c")
        .file("c_src/cuckaroo/interface.cpp")
        .compile("cuckoo");
}

#[cfg(feature = "gpu")]
fn main() {
    cc::Build::new()
        .cuda(true)
        .flag(format!("-DEDGEBITS={}", EDGE_BITS))
        .flag("-arch sm_35")
        .file("c_src/crypto/blake2b-ref.c")
        .file("c_src/cuckaroo/mean.cu")
        .compile("cuckoo");
}