//! Client side of the control channel's token authentication (see the app's `control_auth`):
//! where a client finds the token and the port of a running app.
//!
//! - `--control-token <hex>` / `VECTORCRAFT_CONTROL_TOKEN`
//! - `--control-token-file <path>` / `VECTORCRAFT_CONTROL_TOKEN_FILE`: the bare token, or a port file
//! - `--control-port-file <path>` / `VECTORCRAFT_CONTROL_PORT_FILE`: `{"port","token","pid"}` written by
//!   the app (`vectorcraft --control 0 --control-port-file <path>`); gives both address and token

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Control-client flags.
#[derive(Clone, Debug, Default)]
pub struct ControlClientArgs {
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub port_file: Option<PathBuf>,
}

impl ControlClientArgs {
    /// Consume one control flag; `next` yields its value. `Ok(false)`: not a control flag.
    pub fn take(&mut self, flag: &str, next: &mut dyn Iterator<Item = String>) -> Result<bool, String> {
        let mut value = || next.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag {
            "--control-token" => self.token = Some(value()?),
            "--control-token-file" => self.token_file = Some(PathBuf::from(value()?)),
            "--control-port-file" => self.port_file = Some(PathBuf::from(value()?)),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// `(address from the port file, token)`: flags first, then the environment.
    pub fn resolve(&self) -> Result<(Option<String>, Option<String>), String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let port_file = self.port_file.clone().or_else(|| var("VECTORCRAFT_CONTROL_PORT_FILE").map(PathBuf::from));
        let (addr, file_token) = match &port_file {
            Some(p) => {
                let (port, token) = read_port_file(p)?;
                (Some(format!("127.0.0.1:{port}")), token)
            }
            None => (None, None),
        };
        let token = match (&self.token, &self.token_file) {
            (Some(_), Some(_)) => return Err("use either --control-token or --control-token-file, not both".into()),
            (Some(t), None) => Some(checked(t)?),
            (None, Some(f)) => Some(read_token_file(f)?),
            (None, None) => match file_token {
                Some(t) => Some(t),
                None => token_from_env()?,
            },
        };
        Ok((addr, token))
    }
}

fn checked(token: &str) -> Result<String, String> {
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(token.to_ascii_lowercase())
    } else {
        Err("control token must contain exactly 64 hexadecimal characters".into())
    }
}

/// `VECTORCRAFT_CONTROL_TOKEN`, else the file named by `VECTORCRAFT_CONTROL_TOKEN_FILE`, else none.
pub fn token_from_env() -> Result<Option<String>, String> {
    if let Some(t) = std::env::var("VECTORCRAFT_CONTROL_TOKEN").ok().filter(|v| !v.is_empty()) {
        return checked(&t).map(Some);
    }
    match std::env::var_os("VECTORCRAFT_CONTROL_TOKEN_FILE").filter(|v| !v.is_empty()) {
        Some(f) => read_token_file(Path::new(&f)).map(Some),
        None => Ok(None),
    }
}

/// A token file holds the bare token, or is a port file (`{"token": …}`).
pub fn read_token_file(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = text.trim();
    if text.starts_with('{') {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("{}: {e}", path.display()))?;
        return v.get("token").and_then(Value::as_str).ok_or_else(|| format!("{}: no `token`", path.display())).and_then(checked);
    }
    checked(text)
}

/// `(port, token)` from a port file the app wrote (`token` is null with `--control-no-auth`).
pub fn read_port_file(path: &Path) -> Result<(u16, Option<String>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(text.trim()).map_err(|e| format!("{}: {e}", path.display()))?;
    let port = v.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).ok_or_else(|| format!("{}: no `port`", path.display()))?;
    let token = match v.get("token").and_then(Value::as_str) {
        Some(t) => Some(checked(t)?),
        None => None,
    };
    Ok((port, token))
}
