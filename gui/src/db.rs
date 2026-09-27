//! On-disk project storage: a SQLite file, optionally encrypted with
//! SQLCipher (via `rusqlite`'s `bundled-sqlcipher-vendored-openssl`
//! feature) -- same approach as the `attestation_db` sibling project.
//!
//! A project's hosts (each with its clients nested inside, same shape as
//! before) are stored one JSON blob per row rather than as a fully
//! relational schema -- `HostProjectDict`/`ClientProjectDict` already have
//! a stable serde representation used for the old `.json` project format,
//! and reusing it here means `host_tab.rs`/`client_tab.rs` don't need to
//! change at all, only how the whole tree is read/written to disk.
//!
//! Whether a given file is encrypted is a property of the file itself, not
//! a separate flag: opening it without a key either works (unencrypted)
//! or fails in a way indistinguishable from "wrong password" (SQLCipher
//! doesn't tell the two apart), which is exactly the signal used to ask
//! the user for a password (see `try_open`/`unlock`).
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::project::{HostProjectDict, ProjectFile, PROJECT_FORMAT_VERSION};

/// Result of trying to open a project file without a password.
pub enum OpenOutcome {
    /// Read successfully -- either not encrypted, or (for a project saved
    /// before this app used SQLite storage) a legacy plaintext `.json`
    /// file, transparently upgraded on read.
    Ready(ProjectFile),
    /// Could not be read without a key: encrypted, and a password is
    /// needed (see `unlock`).
    Locked,
}

/// Tries to read `path` as an unencrypted project. Falls back to parsing
/// it as a legacy `.json` project file (the format this app used before
/// switching to SQLite) if it doesn't look like a SQLite database at all,
/// so old projects keep opening exactly as before. Returns `Locked` if
/// neither works, which the caller should treat as "ask for a password".
pub fn try_open(path: &Path) -> Result<OpenOutcome> {
    let conn = Connection::open(path).context("Could not open this file")?;
    if conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))
        .is_ok()
    {
        return Ok(OpenOutcome::Ready(read_project(&conn)?));
    }
    drop(conn);

    if let Ok(text) = std::fs::read_to_string(path) {
        if let Ok(data) = serde_json::from_str::<ProjectFile>(&text) {
            return Ok(OpenOutcome::Ready(data));
        }
    }
    Ok(OpenOutcome::Locked)
}

/// Opens an encrypted project file with the given password. An error here
/// means either a wrong password or a corrupted file -- SQLCipher can't
/// tell those apart, so neither can this.
pub fn unlock(path: &Path, password: &str) -> Result<ProjectFile> {
    let conn = Connection::open(path).context("Could not open this file")?;
    conn.pragma_update(None, "key", password)
        .context("Could not set the password")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))
        .context("Incorrect password, or the file is corrupted")?;
    read_project(&conn)
}

fn read_project(conn: &Connection) -> Result<ProjectFile> {
    let version: u32 = conn
        .query_row("SELECT value FROM meta WHERE key = 'version'", [], |row| {
            row.get::<_, String>(0)
        })
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(PROJECT_FORMAT_VERSION);

    let mut stmt = conn.prepare("SELECT data FROM hosts ORDER BY ord ASC, id ASC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut hosts = Vec::new();
    for row in rows {
        let json = row?;
        hosts.push(
            serde_json::from_str::<HostProjectDict>(&json)
                .context("Could not parse a host stored in this project file")?,
        );
    }
    Ok(ProjectFile { version, hosts })
}

/// Writes `project` to `path` as a fresh SQLite file, encrypted with
/// `password` if one is given (`None` or empty means no encryption). Any
/// existing file at `path` is replaced outright -- this is "Save Entire
/// Project", not an incremental update.
pub fn save(path: &Path, project: &ProjectFile, password: Option<&str>) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path).context("Could not replace the existing file")?;
    }
    let conn = Connection::open(path).context("Could not create the project file")?;
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        conn.pragma_update(None, "key", password)
            .context("Could not set the password")?;
    }
    conn.execute_batch(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, ord INTEGER NOT NULL, data TEXT NOT NULL);
         CREATE INDEX idx_hosts_ord ON hosts(ord);",
    )
    .context("Could not create the database schema")?;
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('version', ?1)",
        params![project.version.to_string()],
    )?;
    for (idx, host) in project.hosts.iter().enumerate() {
        let json = serde_json::to_string(host).context("Could not serialize a host")?;
        conn.execute(
            "INSERT INTO hosts (ord, data) VALUES (?1, ?2)",
            params![idx as i64, json],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// App-level settings and action log -- unlike the project file above,
// these live in a fixed per-user location and apply across every project
// the app ever opens, same split as `attestation_db`'s `db.rs` (its doc
// comment on `settings_path` explains why: they need to stay reachable
// even when the thing they're about, here a given project file, is
// encrypted or not currently open).
// ---------------------------------------------------------------------

/// Root directory for this app's own data (settings, action log, default
/// auto-backup destination) -- distinct from wherever the user's project
/// files themselves happen to live.
pub fn app_data_dir() -> Result<PathBuf> {
    let mut dir = dirs::data_dir().context("Could not determine the user data directory")?;
    dir.push("wireguard-studio");
    std::fs::create_dir_all(&dir).context("Could not create the app data directory")?;
    Ok(dir)
}

fn settings_path() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("settings.json"))
}

fn action_log_path() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("action_log.json"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    /// Off by default -- the user opts in.
    pub auto_backup_enabled: bool,
    /// How often to back up, in hours.
    pub auto_backup_interval_hours: u32,
    /// Destination folder for automatic backups; `None` means the default
    /// (an `auto_backups` subfolder of `app_data_dir()`).
    pub auto_backup_dir: Option<String>,
    /// RFC 3339 timestamp of the last automatic backup, if any.
    pub last_auto_backup_at: Option<String>,
    /// How many recent automatic backups to keep -- older ones are pruned
    /// so they don't accumulate on disk forever.
    pub auto_backup_keep_count: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_backup_enabled: false,
            auto_backup_interval_hours: 24,
            auto_backup_dir: None,
            last_auto_backup_at: None,
            auto_backup_keep_count: 14,
        }
    }
}

impl AppSettings {
    /// The folder automatic backups are currently written to (the user's
    /// choice, or the default).
    pub fn auto_backup_dir_path(&self) -> Result<PathBuf> {
        match &self.auto_backup_dir {
            Some(dir) => Ok(PathBuf::from(dir)),
            None => Ok(app_data_dir()?.join("auto_backups")),
        }
    }
}

/// Loads app settings, or defaults (auto-backup off) if there's no
/// settings file yet or it can't be parsed -- both are normal on first
/// run, not errors worth surfacing.
pub fn load_settings() -> AppSettings {
    settings_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_settings(settings: &AppSettings) -> Result<()> {
    let path = settings_path()?;
    let json = serde_json::to_string_pretty(settings).context("Could not serialize settings")?;
    std::fs::write(path, json).context("Could not write the settings file")?;
    Ok(())
}

/// One entry in the action log (the "Journal" button's window).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLogEntry {
    pub logged_at: String,
    pub message: String,
}

/// The whole action log, newest entries first. Empty (not an error) if
/// there's no log file yet.
pub fn load_action_log() -> Vec<ActionLogEntry> {
    action_log_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_action_log(entries: &[ActionLogEntry]) -> Result<()> {
    let path = action_log_path()?;
    let json = serde_json::to_string_pretty(entries).context("Could not serialize the action log")?;
    std::fs::write(path, json).context("Could not write the action log file")?;
    Ok(())
}

/// Records one user action (project saved/opened, backup made, encryption
/// changed, a host or client added/removed, ...) to the persisted log and
/// returns the entry, timestamped just now.
pub fn log_action(message: impl Into<String>) -> Result<ActionLogEntry> {
    let entry = ActionLogEntry {
        logged_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        message: message.into(),
    };
    let mut entries = load_action_log();
    entries.insert(0, entry.clone());
    save_action_log(&entries)?;
    Ok(entry)
}

/// Empties the action log. Returns how many entries were removed.
pub fn clear_action_log() -> Result<usize> {
    let entries = load_action_log();
    let count = entries.len();
    save_action_log(&[])?;
    Ok(count)
}

/// Writes a timestamped backup copy of `project` into `settings`'s
/// configured auto-backup folder, encrypted the same way as the live
/// project (`password`), and prunes old copies beyond
/// `auto_backup_keep_count`. Returns the path just written.
pub fn run_auto_backup(project: &ProjectFile, password: Option<&str>, settings: &AppSettings) -> Result<PathBuf> {
    let dir = settings.auto_backup_dir_path()?;
    std::fs::create_dir_all(&dir).context("Could not create the auto-backup folder")?;
    let dest = dir.join(format!(
        "wireguard-studio_auto_{}.db",
        chrono::Local::now().format("%Y%m%d_%H%M%S")
    ));
    save(&dest, project, password)?;
    let _ = wgcore::set_owner_only_permissions(&dest);

    let prefix = "wireguard-studio_auto_";
    let mut existing: Vec<PathBuf> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(prefix) && n.ends_with(".db"))
                .unwrap_or(false)
        })
        .collect();
    existing.sort();
    let keep = settings.auto_backup_keep_count.max(1) as usize;
    if existing.len() > keep {
        for old in &existing[..existing.len() - keep] {
            let _ = std::fs::remove_file(old);
        }
    }

    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::HostProjectDict;

    fn sample_project() -> ProjectFile {
        ProjectFile {
            version: PROJECT_FORMAT_VERSION,
            hosts: vec![HostProjectDict {
                name: "office".into(),
                private_key: Some("privkey123".into()),
                ..Default::default()
            }],
        }
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "wireguard-studio-db-test-{}-{}.db",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn round_trips_unencrypted() {
        let path = temp_path("plain");
        let project = sample_project();
        save(&path, &project, None).unwrap();

        match try_open(&path).unwrap() {
            OpenOutcome::Ready(data) => {
                assert_eq!(data.hosts.len(), 1);
                assert_eq!(data.hosts[0].name, "office");
                assert_eq!(data.hosts[0].private_key.as_deref(), Some("privkey123"));
            }
            OpenOutcome::Locked => panic!("unencrypted project reported as locked"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn round_trips_encrypted_and_rejects_wrong_password() {
        let path = temp_path("encrypted");
        let project = sample_project();
        save(&path, &project, Some("s3cret")).unwrap();

        // An encrypted file must not be readable without the key.
        match try_open(&path).unwrap() {
            OpenOutcome::Locked => {}
            OpenOutcome::Ready(_) => panic!("encrypted project opened without a password"),
        }

        assert!(unlock(&path, "wrong password").is_err());

        let data = unlock(&path, "s3cret").unwrap();
        assert_eq!(data.hosts.len(), 1);
        assert_eq!(data.hosts[0].name, "office");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn opens_legacy_plaintext_json_project() {
        let path = temp_path("legacy-json");
        let project = sample_project();
        let json = serde_json::to_string(&project).unwrap();
        std::fs::write(&path, json).unwrap();

        match try_open(&path).unwrap() {
            OpenOutcome::Ready(data) => {
                assert_eq!(data.hosts.len(), 1);
                assert_eq!(data.hosts[0].name, "office");
            }
            OpenOutcome::Locked => panic!("legacy JSON project reported as locked"),
        }
        let _ = std::fs::remove_file(&path);
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wireguard-studio-db-test-dir-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn auto_backup_prunes_older_copies_beyond_keep_count() {
        let dir = temp_dir("auto-backup");
        let settings = AppSettings {
            auto_backup_dir: Some(dir.to_string_lossy().into_owned()),
            auto_backup_keep_count: 2,
            ..AppSettings::default()
        };
        let project = sample_project();

        // Three backups in a row, one kept slot fewer than written.
        for _ in 0..3 {
            run_auto_backup(&project, None, &settings).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }

        let remaining: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(remaining.len(), 2, "expected pruning down to auto_backup_keep_count");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
