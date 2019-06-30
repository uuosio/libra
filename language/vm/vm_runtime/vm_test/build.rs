// build.rs

use std::env;

fn main() {
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

//    println!("cargo:rustc-link-search={}", project_dir); // the "-L" flag
    println!("cargo:rustc-link-search={}", "/Users/newworld/dev/rust/cpp_to_rust"); // the "-L" flag
    println!("cargo:rustc-link-lib=hello"); // the "-l" flag
}
