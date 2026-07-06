// TOML storage for the entry set: one file per user, atomic writes.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::entry::{Entry, OtpKind};
use crate::otp::{Algorithm, decode_secret, validate_digits};

// Parse errors report a position instead of wrapping toml's error:
// its Display renders the offending source line, which may hold a secret.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("no platform data directory available")]
    NoDataDir,
    #[error("failed to read the store file")]
    Read(#[source] io::Error),
    #[error("failed to write the store file")]
    Write(#[source] io::Error),
    #[error("store file is not valid UTF-8")]
    NotUtf8,
    #[error("store file is not valid TOML (line {line})")]
    Parse { line: usize },
    #[error("store file format version {version} is newer than this app supports")]
    UnsupportedVersion { version: u32 },
    #[error("failed to serialize the store")]
    Serialize(#[from] toml::ser::Error),
    #[error("store entry {index}: {problem}")]
    InvalidEntry { index: usize, problem: &'static str },
}

// FIXME: nothing guards against a second running instance; concurrent saves
// are last-write-wins and can drop each other's changes.
pub struct Store {
    path: PathBuf,
}

impl Store {
    // Linux: ~/.local/share/mototp/entries.toml.
    pub fn open_default() -> Result<Self, StoreError> {
        let dir = dirs::data_dir().ok_or(StoreError::NoDataDir)?;
        Ok(Self::at_path(dir.join("mototp").join("entries.toml")))
    }

    fn at_path(path: PathBuf) -> Self {
        Self { path }
    }

    // A missing file is an empty set, not an error: the first run has no store.
    pub fn load(&self) -> Result<Vec<Entry>, StoreError> {
        let Some(bytes) = read_bytes(&self.path).map_err(StoreError::Read)? else {
            return Ok(Vec::new());
        };
        let text = String::from_utf8(bytes).map_err(|_| StoreError::NotUtf8)?;
        let document: Document =
            toml::from_str(&text).map_err(|error| parse_error(&text, &error))?;
        // Refuse newer formats: a re-save would silently drop their fields.
        if document.version > FORMAT_VERSION {
            return Err(StoreError::UnsupportedVersion {
                version: document.version,
            });
        }
        document
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, doc)| doc.into_entry(index + 1))
            .collect()
    }

    pub fn save(&self, entries: &[Entry]) -> Result<(), StoreError> {
        // An invalid entry would serialize fine and then fail every load;
        // reject it in save so one bad write cannot brick the whole store.
        for (position, entry) in entries.iter().enumerate() {
            if let Some(problem) = entry_problem(entry) {
                return Err(StoreError::InvalidEntry {
                    index: position + 1,
                    problem,
                });
            }
        }
        let document = Document {
            version: FORMAT_VERSION,
            entries: entries.iter().map(EntryDoc::from_entry).collect(),
        };
        let text = toml::to_string(&document)?;
        write_bytes_atomic(&self.path, text.as_bytes()).map_err(StoreError::Write)
    }
}

// The invariants load enforces; whatever save writes must load back.
fn entry_problem(entry: &Entry) -> Option<&'static str> {
    if entry.secret.is_empty() {
        return Some("secret is empty");
    }
    if validate_digits(entry.digits).is_err() {
        return Some("code length must be 6 to 8 digits");
    }
    // TOML integers are i64; a larger value would fail serialization.
    match entry.kind {
        OtpKind::Totp { period: 0 } => Some("TOTP period must be greater than zero"),
        OtpKind::Totp { period } if period > i64::MAX as u64 => Some("TOTP period is too large"),
        OtpKind::Hotp { counter } if counter > i64::MAX as u64 => Some("HOTP counter is too large"),
        _ => None,
    }
}

fn parse_error(text: &str, error: &toml::de::Error) -> StoreError {
    let line = match error.span() {
        // Count bytes, not a str slice: the span may miss a char boundary.
        Some(span) => {
            let upto = span.start.min(text.len());
            text.as_bytes()[..upto]
                .iter()
                .filter(|b| **b == b'\n')
                .count()
                + 1
        }
        None => 0,
    };
    StoreError::Parse { line }
}

const FORMAT_VERSION: u32 = 1;

// On-disk model, kept separate so the core types stay serde-free.
// Unknown fields are ignored, leaving room for compatible additions.
#[derive(Serialize, Deserialize)]
struct Document {
    version: u32,
    #[serde(default)]
    entries: Vec<EntryDoc>,
}

#[derive(Serialize, Deserialize)]
struct EntryDoc {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    // base32 without padding, the same alphabet otpauth:// uses.
    secret: String,
    algorithm: String,
    digits: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    period: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    counter: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

impl EntryDoc {
    fn from_entry(entry: &Entry) -> Self {
        let (kind, period, counter) = match entry.kind {
            OtpKind::Totp { period } => ("totp", Some(period), None),
            OtpKind::Hotp { counter } => ("hotp", None, Some(counter)),
        };
        Self {
            kind: kind.to_string(),
            issuer: entry.issuer.clone(),
            label: entry.label.clone(),
            display_name: entry.display_name.clone(),
            secret: data_encoding::BASE32_NOPAD.encode(&entry.secret),
            algorithm: match entry.algorithm {
                Algorithm::Sha1 => "SHA1",
                Algorithm::Sha256 => "SHA256",
                Algorithm::Sha512 => "SHA512",
            }
            .to_string(),
            digits: entry.digits,
            period,
            counter,
            tags: entry.tags.clone(),
        }
    }

    // index is 1-based and only feeds error messages.
    fn into_entry(self, index: usize) -> Result<Entry, StoreError> {
        let invalid = |problem| StoreError::InvalidEntry { index, problem };

        // Values match case-insensitively, same as the otpauth:// parser:
        // the file is meant to survive careful hand edits.
        let kind = if self.kind.eq_ignore_ascii_case("totp") {
            // A hand-edited entry may omit the period; the otpauth default applies.
            let period = self.period.unwrap_or(30);
            if period == 0 {
                return Err(invalid("TOTP period must be greater than zero"));
            }
            OtpKind::Totp { period }
        } else if self.kind.eq_ignore_ascii_case("hotp") {
            OtpKind::Hotp {
                // A counter cannot be guessed: a wrong one desyncs the server.
                counter: self.counter.ok_or(invalid("HOTP entry has no counter"))?,
            }
        } else {
            return Err(invalid("unknown OTP type"));
        };

        let algorithm = if self.algorithm.eq_ignore_ascii_case("SHA1") {
            Algorithm::Sha1
        } else if self.algorithm.eq_ignore_ascii_case("SHA256") {
            Algorithm::Sha256
        } else if self.algorithm.eq_ignore_ascii_case("SHA512") {
            Algorithm::Sha512
        } else {
            return Err(invalid("unsupported algorithm"));
        };

        let secret =
            decode_secret(&self.secret).map_err(|_| invalid("secret is not valid base32"))?;
        validate_digits(self.digits).map_err(|_| invalid("code length must be 6 to 8 digits"))?;

        Ok(Entry {
            issuer: self.issuer,
            label: self.label,
            display_name: self.display_name,
            secret,
            algorithm,
            digits: self.digits,
            kind,
            tags: self.tags,
        })
    }
}

fn read_bytes(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

// Write-then-rename: a crash mid-write leaves the old file intact.
// The temp file sits next to the target; the rename stays on one filesystem.
fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "store path has no parent"))?;
    // The directory and the file hold plaintext secrets: owner-only access,
    // set at creation so no window is open while the secrets are written.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir)?;
    let tmp = path.with_extension("toml.tmp");
    // A crash leftover .tmp may carry looser permissions; recreate it fresh.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    // fsync the directory so the rename itself survives a power loss.
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<Entry> {
        vec![
            Entry {
                issuer: Some("Example".into()),
                label: "alice".into(),
                display_name: Some("Work mail".into()),
                secret: b"12345678901234567890".to_vec(),
                algorithm: Algorithm::Sha1,
                digits: 6,
                kind: OtpKind::Totp { period: 30 },
                tags: vec!["work".into(), "mail".into()],
            },
            Entry {
                issuer: None,
                label: "bob".into(),
                display_name: None,
                secret: b"12345678901234567890123456789012".to_vec(),
                algorithm: Algorithm::Sha256,
                digits: 8,
                kind: OtpKind::Hotp { counter: 5 },
                tags: vec![],
            },
        ]
    }

    #[test]
    fn round_trip_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at_path(dir.path().join("entries.toml"));

        let entries = sample_entries();
        store.save(&entries).unwrap();
        assert_eq!(store.load().unwrap(), entries);
    }

    #[test]
    fn load_without_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at_path(dir.path().join("entries.toml"));
        assert_eq!(store.load().unwrap(), vec![]);
    }

    #[test]
    fn save_creates_missing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at_path(dir.path().join("deep").join("entries.toml"));
        store.save(&sample_entries()).unwrap();
        assert_eq!(store.load().unwrap().len(), 2);
    }

    // Extra fields from compatible format additions must not fail the read.
    #[test]
    fn unknown_fields_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entries.toml");
        fs::write(
            &path,
            "version = 1\n\
             future_top_level = \"x\"\n\
             [[entries]]\n\
             type = \"totp\"\n\
             label = \"alice\"\n\
             secret = \"MZXW6YTBOI\"\n\
             algorithm = \"SHA1\"\n\
             digits = 6\n\
             period = 30\n\
             icon = \"future-field\"\n",
        )
        .unwrap();

        let entries = Store::at_path(path).load().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label, "alice");
    }

    // A newer-format file is refused: re-saving it as v1 would drop fields.
    #[test]
    fn newer_format_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entries.toml");
        fs::write(&path, "version = 2\n").unwrap();

        let error = Store::at_path(path).load().unwrap_err();
        assert!(matches!(
            error,
            StoreError::UnsupportedVersion { version: 2 }
        ));
    }

    // A crash before the rename leaves the old file plus a stale .tmp:
    // the old data must load, and the next save must replace the leftovers.
    #[test]
    fn interrupted_write_keeps_old_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entries.toml");
        let store = Store::at_path(path.clone());

        let old = sample_entries();
        store.save(&old).unwrap();
        fs::write(path.with_extension("toml.tmp"), b"garbage from a crash").unwrap();

        assert_eq!(store.load().unwrap(), old);

        let new = vec![old[1].clone()];
        store.save(&new).unwrap();
        assert_eq!(store.load().unwrap(), new);
        assert!(!path.with_extension("toml.tmp").exists());
    }

    // The parse error must carry a position, not the file text:
    // the quoted line could contain a secret.
    #[test]
    fn parse_error_reports_line_without_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entries.toml");
        fs::write(&path, "version = 1\nsecret = not-toml @@@\n").unwrap();

        let error = Store::at_path(path).load().unwrap_err();
        let message = error.to_string();
        assert!(matches!(error, StoreError::Parse { line: 2 }));
        assert!(!message.contains("not-toml"));
    }

    #[test]
    fn hotp_without_counter_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entries.toml");
        fs::write(
            &path,
            "version = 1\n\
             [[entries]]\n\
             type = \"hotp\"\n\
             label = \"bob\"\n\
             secret = \"MZXW6YTBOI\"\n\
             algorithm = \"SHA1\"\n\
             digits = 6\n",
        )
        .unwrap();

        let error = Store::at_path(path).load().unwrap_err();
        assert!(matches!(error, StoreError::InvalidEntry { index: 1, .. }));
    }

    #[test]
    fn empty_secret_is_rejected_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at_path(dir.path().join("entries.toml"));

        let mut entries = sample_entries();
        entries[0].secret.clear();
        let error = store.save(&entries).unwrap_err();
        assert!(matches!(error, StoreError::InvalidEntry { index: 1, .. }));
        // The failed save must not have touched the disk.
        assert_eq!(store.load().unwrap(), vec![]);
    }
}
