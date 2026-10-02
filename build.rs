// Build script: compile friendshub.proto into Rust types via prost-build.
//
// Resolution order for the .proto directory:
//   1. FRIENDSHUB_PROTO_DIR environment variable
//   2. proto/ next to this crate's manifest — the vendored copy
//
// protoc resolution: a vendored binary is preferred over whatever is on the
// PATH. Ubuntu 22.04 ships protoc 3.12, which rejects proto3 optional fields;
// the vendored binary is recent enough for anything this workspace compiles.
// An explicit PROTOC in the environment still wins, so a developer can pin
// their own build.

use std::env;
use std::path::PathBuf;

fn main() {
    // Pin protoc first, before anything else touches it.
    if env::var("PROTOC").is_err() {
        match protoc_bin_vendored::protoc_bin_path() {
            Ok(path) => {
                // SAFETY: build scripts are single-threaded and this runs
                // before any dependency could be reading the environment.
                unsafe { env::set_var("PROTOC", path); }
            }
            Err(e) => {
                println!("cargo:warning=vendored protoc unavailable: {e}");
            }
        }
    }

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
    println!("cargo:rerun-if-env-changed=PROTOC");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));

    // protoc resolves the .proto file against the include directory, so the
    // file is passed by name and the directory as -I. Passing an absolute
    // file path together with an absolute include path makes protoc look for
    // the file inside the include directory and fail with "File not found".
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
