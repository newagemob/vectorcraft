//! Control-channel authentication and discovery: the same per-launch token handshake as
//! PhotoCraft's control port, plus a port file so a client can find a `--control 0` (random
//! port) server.
//!
//! - The first request on every connection must be
//!   `{"id":…,"method":"auth","params":{"token":"<64 hex>"}}`; it is answered
//!   `{"id":…,"ok":true,"result":{"authenticated":true}}`. Anything else is answered
//!   `{"id":…,"ok":false,"error":"authentication required"}` and the connection is closed.
//! - The token is 32 random bytes as 64 lowercase hex characters: fresh per launch, or given with
//!   `--control-token <hex>` / `--control-token-file <path>` (an existing file is reused, a missing
//!   one is created owner-only).
//! - `--control-port-file <path>` (or `$ORCHA_CONTROL_DIR/vectorcraft.json`) receives
//!   `{"port":<u16>,"token":"<hex>","pid":<u32>}` (owner-only) once the server listens.
//! - `--control-no-auth` keeps the old unauthenticated channel (explicit opt-in).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// The first request on every connection must use this method.
pub const AUTH_METHOD: &str = "auth";
const TOKEN_HEX_LEN: usize = 64;

/// How the control server authenticates and where it announces itself.
#[derive(Clone, Debug, Default)]
pub struct ControlAuth {
    /// `None`: no authentication (`--control-no-auth`).
    pub token: Option<String>,
    /// Where to write `{"port","token","pid"}` once listening.
    pub port_file: Option<PathBuf>,
}

/// Control flags parsed from the command line and environment (`VECTORCRAFT_CONTROL_*`).
#[derive(Clone, Debug, Default)]
pub struct ControlArgs {
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub port_file: Option<PathBuf>,
    pub no_auth: bool,
}

impl ControlArgs {
    /// Defaults from `VECTORCRAFT_CONTROL_TOKEN`, `VECTORCRAFT_CONTROL_TOKEN_FILE`,
    /// `VECTORCRAFT_CONTROL_PORT_FILE` and `VECTORCRAFT_CONTROL_NO_AUTH=1`.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            token: var("VECTORCRAFT_CONTROL_TOKEN"),
            token_file: var("VECTORCRAFT_CONTROL_TOKEN_FILE").map(PathBuf::from),
            port_file: var("VECTORCRAFT_CONTROL_PORT_FILE").map(PathBuf::from),
            no_auth: var("VECTORCRAFT_CONTROL_NO_AUTH").is_some_and(|v| v != "0"),
        }
    }

    /// Consume one control flag (`--control-token`, `--control-token-file`, `--control-port-file`,
    /// `--control-no-auth`); `next` yields its value. `Ok(false)`: not a control flag.
    pub fn take(&mut self, flag: &str, next: &mut dyn Iterator<Item = String>) -> Result<bool, String> {
        let mut value = || next.next().filter(|v| !v.starts_with("--")).ok_or_else(|| format!("{flag} needs a value"));
        match flag {
            "--control-token" => self.token = Some(value()?),
            "--control-token-file" => self.token_file = Some(PathBuf::from(value()?)),
            "--control-port-file" => self.port_file = Some(PathBuf::from(value()?)),
            "--control-no-auth" => self.no_auth = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Environment defaults, then take the control flags out of `args` (up to a `--`):
    /// `(other arguments, control flags)`.
    pub fn split(args: impl IntoIterator<Item = String>) -> Result<(Vec<String>, Self), String> {
        let mut c = Self::from_env();
        let mut rest = Vec::new();
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            if a == "--" {
                rest.push(a);
                rest.extend(it.by_ref());
                break;
            }
            if !c.take(&a, &mut it)? {
                rest.push(a);
            }
        }
        Ok((rest, c))
    }

    /// Resolve the token (fresh per launch unless given) and the port file.
    pub fn resolve(&self) -> Result<ControlAuth, String> {
        let port_file = self
            .port_file
            .clone()
            .or_else(|| std::env::var_os("ORCHA_CONTROL_DIR").filter(|d| !d.is_empty()).map(|d| PathBuf::from(d).join("vectorcraft.json")));
        if self.no_auth {
            return Ok(ControlAuth { token: None, port_file });
        }
        let token = server_token(self.token.as_deref(), self.token_file.as_deref())?;
        Ok(ControlAuth { token: Some(token), port_file })
    }

    /// The token was generated here and is written nowhere a client can read it.
    pub fn token_is_private(&self) -> bool {
        !self.no_auth
            && self.token.is_none()
            && self.token_file.is_none()
            && self.port_file.is_none()
            && std::env::var_os("ORCHA_CONTROL_DIR").is_none()
    }
}

/// [`ControlArgs::split`], or exit with status 2 on a bad control flag.
pub fn split_or_exit(args: impl IntoIterator<Item = String>) -> (Vec<String>, ControlArgs) {
    ControlArgs::split(args).unwrap_or_else(|e| {
        eprintln!("vectorcraft: {e}");
        std::process::exit(2);
    })
}

/// The control server's port and authentication, or exit with status 2 on a bad flag. A token
/// generated here and written nowhere is printed to standard error so a client can use it.
pub fn resolve_or_exit(port: Option<u16>, args: &ControlArgs) -> Option<(u16, ControlAuth)> {
    let port = port?;
    match args.resolve() {
        Ok(auth) => {
            if args.token_is_private()
                && let Some(t) = &auth.token
            {
                eprintln!("vectorcraft: control token: {t}");
            }
            Some((port, auth))
        }
        Err(e) => {
            eprintln!("vectorcraft: {e}");
            std::process::exit(2);
        }
    }
}

/// A 256-bit bearer token from the operating system's CSPRNG, as 64 lowercase hex characters.
pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; TOKEN_HEX_LEN / 2];
    getrandom::fill(&mut bytes).map_err(|e| format!("cannot generate control token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Accept only the fixed-width hexadecimal form [`generate_token`] emits.
pub fn validate_token(token: &str) -> Result<(), String> {
    if token.len() == TOKEN_HEX_LEN && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("control token must contain exactly 64 hexadecimal characters".into())
    }
}

/// Compare tokens without an early exit on the first differing byte.
pub fn token_matches(expected: &str, supplied: &str) -> bool {
    expected.len() == TOKEN_HEX_LEN
        && supplied.len() == TOKEN_HEX_LEN
        && expected.bytes().zip(supplied.bytes()).fold(0u8, |d, (a, b)| d | (a ^ b.to_ascii_lowercase())) == 0
}

/// Check the first request of a connection: `(reply, authenticated)`.
pub fn authenticate(id: Value, method: &str, params: &Value, expected: &str) -> (Value, bool) {
    let supplied = params.get("token").and_then(Value::as_str).unwrap_or("");
    if method == AUTH_METHOD && token_matches(expected, supplied) {
        (json!({"id": id, "ok": true, "result": {"authenticated": true}}), true)
    } else {
        (json!({"id": id, "ok": false, "error": "authentication required"}), false)
    }
}

/// A token file holds the bare token, or is a port file (`{"token": …}`).
pub fn read_token_file(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = text.trim();
    let token = if text.starts_with('{') {
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|v| v.get("token").and_then(Value::as_str).map(str::to_string))
            .ok_or_else(|| format!("{}: no `token` in the port file", path.display()))?
    } else {
        text.to_string()
    };
    validate_token(&token)?;
    Ok(token.to_ascii_lowercase())
}

fn open_private(path: &Path, create_new: bool) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if create_new {
        o.create_new(true);
    } else {
        o.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The server's token: the one given, the one in an existing token file, or a fresh one (written
/// to a missing token file, owner-only).
pub fn server_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, String> {
    if supplied.is_some() && token_file.is_some() {
        return Err("use either --control-token or --control-token-file, not both".into());
    }
    if let Some(t) = supplied {
        validate_token(t)?;
        return Ok(t.to_ascii_lowercase());
    }
    let token = generate_token()?;
    let Some(path) = token_file else { return Ok(token) };
    if path.exists() {
        return read_token_file(path);
    }
    match open_private(path, true) {
        Ok(mut f) => writeln!(f, "{token}").map_err(|e| format!("{}: {e}", path.display())).map(|()| token),
        // Another process created it first.
        Err(_) if path.exists() => read_token_file(path),
        Err(e) => Err(e),
    }
}

/// Write `{"port","token","pid"}` (owner-only; `token` is null without authentication).
pub fn write_port_file(path: &Path, port: u16, token: Option<&str>) -> Result<(), String> {
    let mut f = open_private(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // An existing file keeps its old mode on open: tighten it.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    writeln!(f, "{}", json!({"port": port, "token": token, "pid": std::process::id()})).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vectorcraft-control-auth-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    #[test]
    fn tokens_are_fresh_hex_and_compared_exactly() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_ne!(a, b);
        assert!(validate_token(&a).is_ok());
        assert!(token_matches(&a, &a));
        assert!(token_matches(&a, &a.to_ascii_uppercase()));
        assert!(!token_matches(&a, &b));
        assert!(!token_matches(&a, ""));
        assert!(!token_matches(&a, &a[..63]));
        assert!(validate_token("xyz").is_err());
    }

    #[test]
    fn first_request_must_authenticate() {
        let t = generate_token().unwrap();
        let (r, ok) = authenticate(json!(1), "auth", &json!({"token": t}), &t);
        assert!(ok);
        assert_eq!(r, json!({"id": 1, "ok": true, "result": {"authenticated": true}}));
        let (r, ok) = authenticate(json!(2), "engine.execute", &json!({"token": t}), &t);
        assert!(!ok);
        assert_eq!(r, json!({"id": 2, "ok": false, "error": "authentication required"}));
        assert!(!authenticate(json!(3), "auth", &json!({"token": generate_token().unwrap()}), &t).1);
        assert!(!authenticate(json!(4), "auth", &json!({}), &t).1);
    }

    #[test]
    fn token_file_is_created_then_reused_and_port_file_round_trips() {
        let tf = tmp("token");
        let a = server_token(None, Some(&tf)).unwrap();
        assert_eq!(server_token(None, Some(&tf)).unwrap(), a);
        assert_eq!(read_token_file(&tf).unwrap(), a);
        let pf = tmp("port.json");
        write_port_file(&pf, 4321, Some(&a)).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&pf).unwrap()).unwrap();
        assert_eq!(v["port"], 4321);
        assert_eq!(v["token"], a.as_str());
        assert_eq!(v["pid"], std::process::id());
        assert_eq!(read_token_file(&pf).unwrap(), a);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&pf).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&tf).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(server_token(Some(&a), Some(&tf)).is_err());
        let _ = std::fs::remove_file(&tf);
        let _ = std::fs::remove_file(&pf);
    }

    #[test]
    fn flags_parse() {
        let mut c = ControlArgs::default();
        let mut rest = vec!["/tmp/x.json".to_string()].into_iter();
        assert!(c.take("--control-port-file", &mut rest).unwrap());
        assert_eq!(c.port_file.as_deref(), Some(Path::new("/tmp/x.json")));
        assert!(c.take("--control-no-auth", &mut std::iter::empty()).unwrap());
        assert!(c.no_auth);
        assert!(!c.take("--other", &mut std::iter::empty()).unwrap());
        assert!(c.take("--control-token", &mut std::iter::empty()).is_err());
        assert!(c.resolve().unwrap().token.is_none());
        let (rest, c) = ControlArgs::split(["a", "--control-no-auth", "b", "--", "--control-no-auth"].map(String::from)).unwrap();
        assert_eq!(rest, ["a", "b", "--", "--control-no-auth"]);
        assert!(c.no_auth);
    }
}
