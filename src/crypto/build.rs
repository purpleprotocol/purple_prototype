extern crate cmake;

use cmake::Config;

fn main() {
    let dst = Config::new("c_src")
                 .define("USE_GMP", "0")
                 .define("USE_OPENSSL", "0")
                 .build();
    println!("cargo:rustc-link-search=native={}", dst.display());
    //println!("cargo:rustc-link-lib=static=bls");
}