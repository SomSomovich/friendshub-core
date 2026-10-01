// Build script: compile friendshub.proto into Rust types via prost-build.
//
// The proto file lives in the friendshubB repository, which is private. We do
// not clone it from git — the path is resolved locally.
//
// Resolution order:
//   1. FRIENDSHUB_PROTO_DIR environment variable (directory containing the .proto)
//   2. ../friendshubB/proto relative to this crate's manifest directory
//
// The resulting Rust file is named after the proto package (`fh`), so it
// lands in $OUT_DIR/fh.rs and is pulled in by src/proto/mod.rs via include!.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );

    let proto_dir = match env::var("FRIENDSHUB_PROTO_DIR") {
        Ok(p) => PathBuf::from(p),
        Err(_) => manifest_dir.join("../friendshubB/proto"),
    };

    if !proto_dir.is_dir() {
        panic!(
            "proto directory does not exist: {}. \\
             Set FRIENDSHUB_PROTO_DIR to the directory containing friendshub.proto, \\
             or place the friendshubB repository next to friendshub-core.",
            proto_dir.display()
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

    // protoc resolves the .proto file against the include directory, so the
    // file is passed by name and the directory as -I. Passing an absolute file
    // path together with an absolute include path makes protoc look for the
    // file inside the include directory and fail with "File not found".
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
