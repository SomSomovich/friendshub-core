#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

fail() {
    printf 'build: %s\n' "$1" >&2
    exit 2
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command '$1' was not found in PATH"
    fi
}

require_rust_target() {
    requested_target=$1
    target_to_check=${requested_target%%.*}
    target_list=$(rustup target list --installed) || fail "could not list installed Rust targets with rustup"
    if ! printf '%s\n' "$target_list" | grep -F -x "$target_to_check" >/dev/null 2>&1; then
        fail "Rust target '$target_to_check' is not installed; run: rustup target add $target_to_check"
    fi
}

build_native() {
    require_command cargo
    require_command rustc
    require_command rustup

    native_target=${NATIVE_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}
    if [ -z "$native_target" ]; then
        fail "could not determine the Rust host target; set NATIVE_TARGET explicitly"
    fi
    require_rust_target "$native_target"

    case "$native_target" in
        *-apple-*)
            require_command zig
            if ! cargo zigbuild --help >/dev/null 2>&1; then
                fail "cargo-zigbuild is unavailable; install it with: cargo install cargo-zigbuild"
            fi
            printf 'Building native friendshub-core release for Apple target %s with cargo zigbuild\n' "$native_target"
            cargo zigbuild --release --locked --package friendshub-core --target "$native_target"
            ;;
        *)
            printf 'Building native friendshub-core release for %s with cargo\n' "$native_target"
            cargo build --release --locked --package friendshub-core --target "$native_target"
            ;;
    esac
}

build_wasm() {
    require_command cargo
    require_command rustup
    if ! command -v wasm-pack >/dev/null 2>&1; then
        fail "wasm-pack is required to generate browser JS glue; install it with: cargo install wasm-pack"
    fi
    require_rust_target wasm32-unknown-unknown

    printf 'Building browser package for wasm32-unknown-unknown\n'
    wasm-pack build bindings/wasm \
        --target web \
        --release \
        --no-gitignore \
        --out-dir ../../target/wasm-browser
    printf 'Browser-ready WASM package: %s/target/wasm-browser\n' "$REPO_ROOT"
}

case ${1:-} in
    native)
        build_native
        ;;
    wasm)
        build_wasm
        ;;
    all)
        build_native
        build_wasm
        ;;
    *)
        printf 'Usage: %s {native|wasm|all}\n' "$0" >&2
        exit 2
        ;;
esac
