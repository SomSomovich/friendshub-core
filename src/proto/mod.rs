//! Prost-generated types from friendshub.proto.
//!
//! Compiled at build time by build.rs. The source .proto lives in the
//! friendshubB repository; its path is resolved via FRIENDSHUB_PROTO_DIR or
//! a sibling directory fallback.
//!
//! The generated file is named after the proto package (`fh`), hence fh.rs.

#![allow(clippy::all)]
#![allow(rustdoc::all)]

include!(concat!(env!("OUT_DIR"), "/fh.rs"));
