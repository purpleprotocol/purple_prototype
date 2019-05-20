#[cfg(not(feature = "gpu"))]
fn main() {
    cc::Build::new()
        .cpp(true)
        .flag("-std=c++11")
        .flag("-mavx2")
        .flag("-DNSIPHASH=8")
        .flag("-DEDGEBITS=29")
        .flag("-Wno-deprecated")
        .flag("-Wno-unused-parameter")
        .file("c_src/crypto/blake2b-ref.c")
        .file("c_src/cuckaroo/mean.cpp")
        .compile("cuckoo");
}

#[cfg(feature = "gpu")]
fn main() {
    cc::Build::new()
        .cuda(true)
        .flag("-DEDGEBITS=29")
        .flag("-arch sm_35")
        .file("c_src/crypto/blake2b-ref.c")
        .file("c_src/cuckaroo/mean.cu")
        .compile("cuckoo");
}