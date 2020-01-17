/*
  Copyright (C) 2018-2020 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.

  This is a modified version of the following file:
  https://github.com/mimblewimble/grin-miner/blob/master/cuckoo-miner/src/build.rs
*/

#[cfg(any(feature = "cpu", feature = "gpu"))]
use cmake::Config;

#[cfg(any(feature = "cpu", feature = "gpu"))]
use std::{env, fs};

#[cfg(any(feature = "cpu", feature = "gpu"))]
use std::path::PathBuf;

#[cfg(any(feature = "cpu", feature = "gpu"))]
use fs_extra::dir::*;

#[cfg(feature = "gpu")]
const BUILD_CUDA_PLUGINS: &str = "TRUE";
#[cfg(feature = "cpu")]
const BUILD_CUDA_PLUGINS: &str = "FALSE";

#[cfg(any(feature = "cpu", feature = "gpu"))]
fn fail_on_empty_directory(name: &str) {
    if fs::read_dir(name).unwrap().count() == 0 {
        println!(
            "The `{}` directory is empty. Did you forget to pull the submodules?",
            name
        );
        println!("Try `git submodule update --init --recursive`");
        panic!();
    }
}

#[cfg(not(any(feature = "cpu", feature = "gpu")))]
fn main() {}

#[cfg(any(feature = "cpu", feature = "gpu"))]
fn main() {
    fail_on_empty_directory("cuckoo_src/cuckoo");
    let path_str = env::var("OUT_DIR").unwrap();
    let mut out_path = PathBuf::from(&path_str);
    out_path.pop();
    out_path.pop();
    out_path.pop();
    let mut plugin_path = PathBuf::from(&path_str);
    plugin_path.push("build");
    plugin_path.push("plugins");
    // Collect the files and directories we care about
    let p = PathBuf::from("cuckoo_src");
    let dir_content = match get_dir_content(p) {
        Ok(c) => c,
        Err(e) => panic!("Error getting directory content: {}", e),
    };
    for d in dir_content.directories {
        let file_content = get_dir_content(d).unwrap();
        for f in file_content.files {
            println!("cargo:rerun-if-changed={}", f);
        }
    }
    for f in dir_content.files {
        println!("cargo:rerun-if-changed={}", f);
    }

    let dst = Config::new("cuckoo_src")
        .define("BUILD_CUDA_PLUGINS", BUILD_CUDA_PLUGINS) //whatever flags go here
        //.cflag("-foo") //and here
        .build_target("")
        .build();

    println!("Plugin path: {:?}", plugin_path);
    println!("OUT PATH: {:?}", out_path);
    let mut options = CopyOptions::new();
    options.overwrite = true;
    if let Err(e) = copy(plugin_path, out_path, &options) {
        println!("{:?}", e);
    }

    println!("cargo:rustc-link-search=native={}", dst.display());
}
