//! Android-only link shim for `__clear_cache`.
//!
//! frida-gum (compiled into `frida-sys`) calls `__clear_cache`, a compiler-rt builtin,
//! from `gum_clear_cache`. `rustc` links the final binary with `-nodefaultlibs`, so the
//! NDK's clang builtins archive — which provides `__clear_cache` — is never pulled in,
//! and the link fails with `undefined symbol: __clear_cache`.
//!
//! Here we locate `libclang_rt.builtins-<arch>-android.a` in the NDK toolchain and add
//! it to the link. This runs only when targeting Android; on every other target it is a
//! no-op (so host builds/`cargo check` are unaffected, and there is no vendored `.a`).

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return;
    }

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let rt_arch = match arch.as_str() {
        "aarch64" => "aarch64",
        "arm" => "arm",
        "x86" => "i686",
        "x86_64" => "x86_64",
        other => other,
    };
    let lib_name = format!("clang_rt.builtins-{rt_arch}-android");
    let file_name = format!("lib{lib_name}.a");

    let Some(dir) = locate_builtins_dir(&file_name) else {
        println!(
            "cargo:warning=FGGB: could not find {file_name} in the NDK. Set ANDROID_NDK_HOME \
             or build via cargo-ndk; otherwise the link will fail with `undefined symbol: \
             __clear_cache`."
        );
        return;
    };

    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static={lib_name}");
}

/// Find the directory containing `file_name` inside the NDK LLVM toolchain.
fn locate_builtins_dir(file_name: &str) -> Option<PathBuf> {
    // Candidate `.../toolchains/llvm/prebuilt/<host>` roots.
    let mut roots: Vec<PathBuf> = Vec::new();

    for key in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME", "ANDROID_NDK"] {
        if let Ok(ndk) = std::env::var(key) {
            roots.push(PathBuf::from(&ndk).join("toolchains/llvm/prebuilt"));
        }
    }
    // cargo-ndk exposes the sysroot; the toolchain root is a couple levels up from it.
    for key in ["CARGO_NDK_SYSROOT_PATH", "CARGO_NDK_SYSROOT_LIBS_PATH"] {
        if let Ok(sysroot) = std::env::var(key) {
            if let Some(prebuilt_host) = Path::new(&sysroot)
                .ancestors()
                .find(|p| p.file_name().map(|n| n == "sysroot").unwrap_or(false))
                .and_then(|p| p.parent())
            {
                roots.push(prebuilt_host.to_path_buf());
            }
        }
    }

    for root in roots {
        if let Some(found) = find_file(&root, file_name, 8) {
            return found.parent().map(Path::to_path_buf);
        }
    }
    None
}

/// Bounded-depth search for `file_name` under `dir`.
fn find_file(dir: &Path, file_name: &str, depth: usize) -> Option<PathBuf> {
    if depth == 0 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path.file_name().map(|n| n == file_name).unwrap_or(false) {
            return Some(path);
        }
    }
    for sub in subdirs {
        if let Some(found) = find_file(&sub, file_name, depth - 1) {
            return Some(found);
        }
    }
    None
}
