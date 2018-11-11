extern crate cc;

fn main() {
  cc::Build::new()
          .file("c_src/BitArray.c")
          .file("c_src/itc.c")
          .compile("jump");
}