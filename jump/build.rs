extern crate cc;

fn main() {
  cc::Build::new()
          .file("c_src/jump.c")
          .compile("jump");
}