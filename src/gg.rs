//! GameGuardian discovery (on-device, needs root).
//!
//! GG randomizes its package + app label per install, so we identify it structurally:
//! the marker file `/data/data/<pkg>/files/<GG-xxxx>/version.gg` is unique to GG. The
//! running UI process is the one whose `/proc/<pid>/cmdline` first token equals `<pkg>`.

use std::fs;
use std::path::Path;

/// Resolve GG's package name. `FGGB_GG_PACKAGE` overrides discovery.
pub fn find_package() -> Option<String> {
    if let Ok(pkg) = std::env::var("FGGB_GG_PACKAGE") {
        if !pkg.is_empty() {
            return Some(pkg);
        }
    }
    for app in fs::read_dir("/data/data").ok()?.flatten() {
        let files = app.path().join("files");
        let Ok(subdirs) = fs::read_dir(&files) else { continue };
        for sub in subdirs.flatten() {
            if sub.path().join("version.gg").is_file() {
                return app.file_name().to_str().map(str::to_string);
            }
        }
    }
    None
}

/// Read GG's version string from its `version.gg` marker (e.g. "16142:101.1"), if present.
pub fn version(package: &str) -> Option<String> {
    let base = Path::new("/data/data").join(package).join("files");
    for sub in fs::read_dir(&base).ok()?.flatten() {
        let marker = sub.path().join("version.gg");
        if marker.is_file() {
            return fs::read_to_string(marker).ok().map(|s| s.trim().to_string());
        }
    }
    None
}

/// Find the running pid of `package` (its UI process) via `/proc/<pid>/cmdline`.
pub fn find_pid(package: &str) -> Option<u32> {
    let want = package.as_bytes();
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else { continue };
        // cmdline is NUL-separated; the first token is the process/package name.
        let first = cmdline.split(|&b| b == 0).next().unwrap_or(&[]);
        if first == want {
            return Some(pid);
        }
    }
    None
}
