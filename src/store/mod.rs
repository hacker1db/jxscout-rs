//! On-disk storage: the project directory tree and the SQLite index.

pub mod db;
pub mod paths;

use std::io;
use std::path::{Component, Path, PathBuf};

pub use db::{AssetRow, Db, FindingRow};

/// Validate a project name as one safe directory name (R-33).
pub fn validate_project_name(name: &str) -> Result<(), String> {
    let ok_chars = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if name.is_empty() || name.len() > 64 || !ok_chars || name == "." || name == ".." {
        return Err(format!(
            "invalid project name `{name}`: use 1-64 characters from [A-Za-z0-9._-]"
        ));
    }
    Ok(())
}

/// Writes files under one project directory, never outside it.
#[derive(Debug, Clone)]
pub struct AssetStore {
    root: PathBuf,
}

impl AssetStore {
    /// Create (if needed) `<output_dir>/<project>`.
    pub fn new(output_dir: &Path, project: &str) -> io::Result<Self> {
        validate_project_name(project)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let root = output_dir.join(project);
        std::fs::create_dir_all(&root)?;
        // The output dir itself may be a symlink the user chose, but the
        // project dir inside it must be a real directory (R-33).
        if std::fs::symlink_metadata(&root)?.file_type().is_symlink() {
            return Err(symlink_error(&root));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write `bytes` at `rel` (a path produced by [`paths`]) and return the
    /// path actually used, relative to the project root.
    ///
    /// Collisions are resolved deterministically (R-32, upstream #19):
    /// * if a *directory* component already exists as a **file**, the
    ///   directory `<name>.d` is used instead;
    /// * if the *file* already exists as a **directory**, the file is written
    ///   inside it as `(file)<name>`.
    ///
    /// Symlinks inside the tree are never followed (R-33).
    pub fn write(&self, rel: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
        let comps: Vec<&std::ffi::OsStr> = rel
            .components()
            .map(|c| match c {
                Component::Normal(s) => Ok(s),
                other => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("refusing unsafe path component {other:?} in {rel:?}"),
                )),
            })
            .collect::<io::Result<_>>()?;
        let Some((file_name, dirs)) = comps.split_last() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
        };

        let mut cur = self.root.clone();
        let mut used = PathBuf::new();
        for dir in dirs {
            let name = self.resolve_dir(&cur, dir)?;
            cur.push(&name);
            used.push(&name);
        }

        let mut target = cur.join(file_name);
        let mut used_name = PathBuf::from(file_name);
        match std::fs::symlink_metadata(&target) {
            Ok(m) if m.file_type().is_symlink() => return Err(symlink_error(&target)),
            Ok(m) if m.is_dir() => {
                let inner = format!("(file){}", file_name.to_string_lossy());
                target.push(&inner);
                used_name.push(&inner);
                if std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
                    return Err(symlink_error(&target));
                }
            }
            _ => {}
        }
        // Write to a temp file and rename so readers never see half a file.
        // The counter keeps concurrent writes of the same file from sharing
        // a temp name.
        static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut tmp_name = target.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(format!(".tmp-{}-{n}", std::process::id()));
        let tmp = target.with_file_name(tmp_name);
        // `create_new` (O_EXCL) fails instead of following a symlink that
        // someone planted at the temp path.
        let written = (|| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(bytes)
        })();
        if let Err(e) = written {
            // Don't leave half-written temp files behind (but never delete
            // something we didn't create: `create_new` failed → not ours).
            if e.kind() != io::ErrorKind::AlreadyExists {
                let _ = std::fs::remove_file(&tmp);
            }
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &target) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        used.push(used_name);
        Ok(used)
    }

    /// Pick the directory name to use for component `dir` under `parent`,
    /// creating it if needed.
    fn resolve_dir(&self, parent: &Path, dir: &std::ffi::OsStr) -> io::Result<std::ffi::OsString> {
        let mut name = dir.to_os_string();
        for attempt in 0..8 {
            let candidate = parent.join(&name);
            match std::fs::symlink_metadata(&candidate) {
                Ok(m) if m.file_type().is_symlink() => return Err(symlink_error(&candidate)),
                Ok(m) if m.is_dir() => return Ok(name),
                Ok(_) => {
                    // Exists as a file: deterministic alternate name.
                    name = dir.to_os_string();
                    name.push(if attempt == 0 {
                        ".d".to_string()
                    } else {
                        format!(".d{attempt}")
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    match std::fs::create_dir(&candidate) {
                        Ok(()) => return Ok(name),
                        // Another task created it concurrently: re-check.
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other(format!(
            "could not find a free directory name for {dir:?}"
        )))
    }
}

fn symlink_error(p: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("refusing to write through symlink {p:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_names() {
        assert!(validate_project_name("default").is_ok());
        assert!(validate_project_name("att.com").is_ok());
        for bad in ["", ".", "..", "a/b", "../x", "a b", &"x".repeat(65)] {
            assert!(validate_project_name(bad).is_err(), "{bad}");
        }
    }

    /// Regression for upstream #19: a path component that already exists as
    /// a file must not abort the save with "not a directory".
    #[test]
    fn file_vs_dir_collisions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AssetStore::new(tmp.path(), "att.com").unwrap();
        // `levelblue.com` saved as a *file* first …
        let first = store.write(Path::new("levelblue.com"), b"page").unwrap();
        assert_eq!(first, PathBuf::from("levelblue.com"));
        // … then something needs it as a directory.
        let second = store.write(Path::new("levelblue.com/a.js"), b"js").unwrap();
        assert_eq!(second, PathBuf::from("levelblue.com.d/a.js"));
        // Deterministic: same input, same output.
        assert_eq!(
            store
                .write(Path::new("levelblue.com/a.js"), b"js2")
                .unwrap(),
            second
        );

        // The reverse: a directory exists where a file is wanted.
        store.write(Path::new("x/y/z.js"), b"1").unwrap();
        let p = store.write(Path::new("x/y"), b"2").unwrap();
        assert_eq!(p, PathBuf::from("x/y/(file)y"));
        assert_eq!(std::fs::read(store.root().join(&p)).unwrap(), b"2");
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AssetStore::new(tmp.path(), "p").unwrap();
        assert!(store.write(Path::new("../escape.js"), b"x").is_err());
        assert!(store.write(Path::new("/abs.js"), b"x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_project_dir_and_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("proj")).unwrap();
        assert!(AssetStore::new(tmp.path(), "proj").is_err());

        let store = AssetStore::new(tmp.path(), "ok").unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, b"keep").unwrap();
        std::os::unix::fs::symlink(&secret, store.root().join("x.js")).unwrap();
        assert!(store.write(Path::new("x.js"), b"overwrite").is_err());
        assert_eq!(std::fs::read(&secret).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let store = AssetStore::new(tmp.path(), "p").unwrap();
        std::os::unix::fs::symlink(outside.path(), store.root().join("link")).unwrap();
        let err = store.write(Path::new("link/evil.js"), b"x").unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }
}
