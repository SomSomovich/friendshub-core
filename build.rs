// Build script: compile friendshub.proto into Rust types via prost-build.
//
// Resolution order for the .proto directory:
//   1. FRIENDSHUB_PROTO_DIR environment variable
//   2. proto/ next to this crate's manifest - the vendored copy
//
// protoc itself must already be on PATH or named by the PROTOC environment
// variable. The build cannot vendor one: a dependency earlier in the graph
// (spqr, through libsignal-protocol) runs its own build script before this
// one, and it also needs protoc. Installing the compiler once for the whole
// build is the only arrangement that works for both. CI does that in a setup
// step; a developer needs it locally.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );

    let proto_dir = match env::var("FRIENDSHUB_PROTO_DIR") {
        Ok(p) => PathBuf::from(p),
        Err(_) => manifest_dir.join("proto"),
    };

    if !proto_dir.is_dir() {
        panic!(
            "proto directory does not exist: {}. \\
             Set FRIENDSHUB_PROTO_DIR to the directory containing friendshub.proto, \\
             or place a copy at {}/proto/friendshub.proto.",
            proto_dir.display(),
            manifest_dir.display()
        );
    }

    let proto_file = proto_dir.join("friendshub.proto");
    if !proto_file.is_file() {
        panic!("friendshub.proto not found in {}", proto_dir.display());
    }

    println!("cargo:rerun-if-changed={}", proto_file.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FRIENDSHUB_PROTO_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));

    let file_name = "friendshub.proto";

    let mut config = prost_build::Config::new();
    config.out_dir(&out_dir);
    config
        .compile_protos(&[file_name], &[proto_dir.as_path()])
        .unwrap_or_else(|e| panic!("prost-build failed to compile friendshub.proto: {e}"));

    let generated = out_dir.join("fh.rs");
    if !generated.is_file() {
        panic!(
            "prost-build did not produce fh.rs in {}. Check the package name in friendshub.proto.",
            out_dir.display()
        );
    }
}
