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
use std::fs;
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
    for rest_file in [
        "common.proto",
        "identity.proto",
        "chat.proto",
        "community.proto",
    ] {
        let rest_path = proto_dir.join("rest").join(rest_file);
        if !rest_path.is_file() {
            panic!("REST protobuf schema not found: {}", rest_path.display());
        }
        println!("cargo:rerun-if-changed={}", rest_path.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FRIENDSHUB_PROTO_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));

    let mut config = prost_build::Config::new();
    config.out_dir(&out_dir);
    config.type_attribute(
        ".fh.rest",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );
    config.type_attribute(
        ".fh.rest",
        "#[serde(rename_all = \"camelCase\", deny_unknown_fields)]",
    );
    config.field_attribute(".fh.rest", "#[serde(default)]");
    // The backend keeps its canonical schema under `proto/`, while its
    // imports are repository-relative (`proto/rest/...`). Keep `proto_dir`
    // as the direct include root for the vendored core schema and add its
    // parent so the backend's repository-relative imports resolve too.
    let schema_source = fs::read_to_string(&proto_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", proto_file.display()));

    let rest_files = [
        "common.proto",
        "identity.proto",
        "chat.proto",
        "community.proto",
    ];
    let rest_sources = rest_files
        .iter()
        .filter(|file| {
            let short_import = format!("import \"rest/{file}\"");
            let repository_import = format!("import \"proto/rest/{file}\"");
            !schema_source.contains(&short_import) && !schema_source.contains(&repository_import)
        })
        .map(|file| proto_dir.join("rest").join(file));

    let mut proto_files = vec![proto_file.clone()];
    proto_files.extend(rest_sources);

    let mut include_dirs = vec![proto_dir.clone()];
    if let Some(repository_root) = proto_dir.parent() {
        if !repository_root.as_os_str().is_empty() && repository_root != proto_dir {
            include_dirs.push(repository_root.to_path_buf());
        }
    }

    config
        .compile_protos(&proto_files, &include_dirs)
        .unwrap_or_else(|e| panic!("prost-build failed to compile friendshub.proto: {e}"));

    let generated = out_dir.join("fh.rs");
    if !generated.is_file() {
        panic!(
            "prost-build did not produce fh.rs in {}. Check the package name in friendshub.proto.",
            out_dir.display()
        );
    }
}
