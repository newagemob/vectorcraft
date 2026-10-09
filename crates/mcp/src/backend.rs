//! Where MCP tool calls end up: a control-channel method call.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

/// Something that answers control-channel methods (`engine.execute`, `document.inspect`,
/// `ui.pointer`, `ui.render`, `app.export`, …). See `vectorcraft_ui_egui::control` for the list.
pub trait Backend {
    /// Call one method. `Ok` carries the `result`, `Err` the error message.
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
    /// True when a real UI is attached (`ui.*` methods like `ui.key` / `ui.inspect` work).
    fn has_ui(&self) -> bool;
    /// Short human description ("headless", "remote 127.0.0.1:7979").
    fn describe(&self) -> String;
}

/// A running VectorCraft app, reached through its loopback control port.
pub struct Remote {
    addr: String,
    conn: Option<(BufReader<TcpStream>, TcpStream)>,
    next_id: u64,
    /// Sent as `auth {token}` on every new connection (see `control_client`).
    token: Option<String>,
}

impl Remote {
    /// Connect to `addr` (e.g. `127.0.0.1:7979`), failing fast when nothing is listening.
    /// The token comes from the environment (`crate::control_client::token_from_env`).
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let token = crate::control_client::token_from_env().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Self::connect_with_token(addr, token)
    }

    /// Connect to `addr`, authenticating with `token` when the app requires one.
    pub fn connect_with_token(addr: &str, token: Option<String>) -> std::io::Result<Self> {
        let mut r = Self { addr: addr.to_string(), conn: None, next_id: 1, token };
        r.reconnect()?;
        Ok(r)
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    fn reconnect(&mut self) -> std::io::Result<()> {
        self.conn = None;
        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, format!("cannot resolve {}", self.addr));
        for sa in self.addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&sa, Duration::from_millis(800)) {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    // The app answers within 60 s (its own timeout); leave headroom.
                    s.set_read_timeout(Some(Duration::from_secs(90))).ok();
                    let read = s.try_clone()?;
                    let mut reader = BufReader::new(read);
                    let mut s = s;
                    if let Some(token) = &self.token {
                        authenticate(&mut reader, &mut s, token)?;
                    }
                    self.conn = Some((reader, s));
                    return Ok(());
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn roundtrip(&mut self, line: &str) -> std::io::Result<String> {
        if self.conn.is_none() {
            self.reconnect()?;
        }
        let Some((reader, writer)) = self.conn.as_mut() else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected to the app"));
        };
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        let mut reply = String::new();
        if reader.read_line(&mut reply)? == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "control channel closed"));
        }
        Ok(reply)
    }
}

impl Backend for Remote {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({"id": id, "method": method, "params": params}).to_string();
        // One retry with a fresh connection (the app may have restarted).
        let reply = match self.roundtrip(&line) {
            Ok(r) => r,
            Err(_) => {
                self.conn = None;
                self.roundtrip(&line).map_err(|e| {
                    self.conn = None;
                    format!("VectorCraft app at {} is not reachable: {e}", self.addr)
                })?
            }
        };
        let v: Value = serde_json::from_str(reply.trim()).map_err(|e| format!("bad reply from app: {e}"))?;
        if v.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(v.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(v.get("error").and_then(Value::as_str).unwrap_or("unknown error").to_string())
        }
    }

    fn has_ui(&self) -> bool {
        true
    }

    fn describe(&self) -> String {
        format!("remote {}", self.addr)
    }
}

/// Send `auth {token}` and require `{"ok": true}`.
fn authenticate(reader: &mut BufReader<TcpStream>, writer: &mut TcpStream, token: &str) -> std::io::Result<()> {
    writeln!(writer, "{}", json!({"id": 0, "method": "auth", "params": {"token": token}}))?;
    writer.flush()?;
    let mut reply = String::new();
    reader.read_line(&mut reply)?;
    let v: Value = serde_json::from_str(reply.trim()).unwrap_or(Value::Null);
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        let why = v.get("error").and_then(Value::as_str).unwrap_or("no reply");
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("control channel refused the token: {why}")))
    }
}
