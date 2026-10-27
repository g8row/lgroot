//! Where we remember per-TV pairing keys.
//!
//! A key is a credential: it lets this computer drive the TV without asking
//! again. Keep it out of the working directory and readable only by us.

use std::fs;
use std::path::PathBuf;

fn base_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join("Library/Application Support/LGroot");
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("LGroot");
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("lgroot");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/lgroot");
    }
    std::env::temp_dir().join("lgroot")
}

fn key_path(ip: &str) -> PathBuf {
    let safe: String = ip
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    base_dir().join(format!("clientkey-{safe}.txt"))
}

pub fn load(ip: &str) -> String {
    fs::read_to_string(key_path(ip))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn save(ip: &str, key: &str) {
    let path = key_path(ip);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::write(&path, key).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
}
