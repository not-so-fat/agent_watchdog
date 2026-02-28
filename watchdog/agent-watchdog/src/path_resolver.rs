//! Path resolution utilities for Agent-WatchDog.
//!
//! Resolves relative file paths to absolute paths by reading
//! the Current Working Directory of the triggering process
//! from `/proc/<pid>/cwd`.

use std::path::{Path, PathBuf};

use log::debug;

/// Resolve a filename to an absolute path.
///
/// If `filename` is already absolute (starts with `/`), return it as-is.
/// Otherwise, read `/proc/<pid>/cwd` to determine the process's working
/// directory and join them.
///
/// Falls back to the raw `filename` if `/proc/<pid>/cwd` is unreadable
/// (e.g., process exited, permission denied, or `/proc` is not mounted).
pub fn resolve_path(pid: u32, filename: &str) -> String {
    // Already absolute — nothing to resolve.
    if filename.starts_with('/') {
        return filename.to_string();
    }

    // Empty or special filenames — return as-is.
    if filename.is_empty() {
        return filename.to_string();
    }

    match read_proc_cwd(pid) {
        Some(cwd) => {
            let full = cwd.join(filename);
            // Canonicalize components like `..` and `.` without
            // requiring the path to actually exist on this host.
            let resolved = normalize_path(&full);
            debug!(
                "Resolved: pid={} cwd={} + {} → {}",
                pid,
                cwd.display(),
                filename,
                resolved
            );
            resolved
        }
        None => {
            debug!(
                "Could not read /proc/{}/cwd — using raw filename: {}",
                pid, filename
            );
            filename.to_string()
        }
    }
}

/// Read the CWD of a process from `/proc/<pid>/cwd`.
///
/// This is a symlink that points to the process's current working
/// directory.  We use `readlink` rather than `canonicalize` to avoid
/// following further symlinks within the CWD path itself.
fn read_proc_cwd(pid: u32) -> Option<PathBuf> {
    let link = format!("/proc/{}/cwd", pid);
    std::fs::read_link(&link).ok()
}

/// Normalize a path by resolving `.` and `..` components without
/// touching the filesystem.
///
/// Unlike `std::fs::canonicalize`, this does not require the path
/// to exist and does not resolve symlinks.
fn normalize_path(path: &Path) -> String {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {
                // skip `.`
            }
            other => {
                components.push(other);
            }
        }
    }

    let result: PathBuf = components.iter().collect();
    result.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_path_unchanged() {
        assert_eq!(resolve_path(99999, "/etc/shadow"), "/etc/shadow");
    }

    #[test]
    fn empty_filename_unchanged() {
        assert_eq!(resolve_path(99999, ""), "");
    }

    #[test]
    fn normalize_removes_dot_dot() {
        let p = Path::new("/home/user/../etc/shadow");
        assert_eq!(normalize_path(p), "/etc/shadow");
    }

    #[test]
    fn normalize_removes_dot() {
        let p = Path::new("/home/./user/./file");
        assert_eq!(normalize_path(p), "/home/user/file");
    }

    #[test]
    fn normalize_complex() {
        let p = Path::new("/a/b/c/../../d/./e");
        assert_eq!(normalize_path(p), "/a/d/e");
    }
}
