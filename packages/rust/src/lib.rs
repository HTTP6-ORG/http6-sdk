//! Local WASIX 02 pilot adapter.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const PROFILE: &str = "http6-wasix-delegation-02";
#[derive(Clone)]
pub struct Response {
    pub status: u16,
    pub body: Value,
    pub request_bytes: Vec<u8>,
}
pub struct PilotClient {
    agent: String,
    ledger: String,
    binary: PathBuf,
}
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn pin(s: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    {
        return Err("valid independently configured trust pin required".into());
    }
    Ok(())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn temp() -> Result<Scratch> {
    let mut random = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let p = std::env::temp_dir().join(format!("http6-sdk-{}", hex(&random)));
    fs::DirBuilder::new().mode(0o700).create(&p)?;
    Ok(Scratch(p))
}
fn evidence(path: &Path) -> Result<Value> {
    let b = fs::read(path)?;
    if b.len() > 10 * 1024 * 1024 {
        return Err("evidence limit".into());
    }
    let v: Value = serde_json::from_slice(&b)?;
    if !v.is_object() {
        return Err("invalid evidence".into());
    }
    Ok(v)
}
fn same(a: &Value, b: &Value, keys: &[&str]) -> Result<()> {
    for k in keys {
        if a.get(*k).is_none() || a.get(*k) != b.get(*k) {
            return Err(format!("evidence mismatch: {k}").into());
        }
    }
    Ok(())
}
impl PilotClient {
    pub fn attach(state: &Path, binary: &Path) -> Result<Self> {
        let c: Value = serde_json::from_slice(&fs::read(state.join("connections.json"))?)?;
        if c["profile"] != PROFILE {
            return Err("profile mismatch".into());
        }
        let agent = c["agent"]
            .as_str()
            .ok_or("agent socket missing")?
            .to_string();
        let ledger = c["ledger"]
            .as_str()
            .ok_or("ledger socket missing")?
            .to_string();
        Ok(Self {
            agent,
            ledger,
            binary: binary.to_path_buf(),
        })
    }
    fn request(&self, socket: &str, method: &str, path: &str, body: &[u8]) -> Result<(u16, Value)> {
        let mut c = UnixStream::connect(socket)?;
        c.set_read_timeout(Some(Duration::from_secs(15)))?;
        write!(c,"{method} {path} HTTP/1.0\r\nHost: agent.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())?;
        c.write_all(body)?;
        let mut raw = Vec::new();
        c.take(10 * 1024 * 1024 + 1).read_to_end(&mut raw)?;
        if raw.len() > 10 * 1024 * 1024 {
            return Err("response limit".into());
        }
        let n = raw
            .windows(4)
            .position(|x| x == b"\r\n\r\n")
            .ok_or("invalid HTTP response")?;
        let headers = std::str::from_utf8(&raw[..n])?;
        let status = headers
            .split_whitespace()
            .nth(1)
            .ok_or("missing status")?
            .parse()?;
        Ok((status, serde_json::from_slice(&raw[n + 4..])?))
    }
    pub fn invoke(&self, proposal: &Value) -> Result<Response> {
        self.invoke_raw(&serde_json::to_vec(proposal)?)
    }
    pub fn invoke_raw(&self, raw: &[u8]) -> Result<Response> {
        if raw.len() > 65536 {
            return Err("request limit".into());
        }
        let (status, body) = self.request(&self.agent, "POST", "/http6/v0/propose", raw)?;
        if !body.is_object() {
            return Err("invalid response".into());
        }
        Ok(Response {
            status,
            body,
            request_bytes: raw.to_vec(),
        })
    }
    pub fn events(&self) -> Result<Value> {
        let (status, rows) = self.request(&self.ledger, "GET", "/http6/v0/events", b"")?;
        if status != 200 || !rows.is_array() {
            return Err("ledger unavailable".into());
        }
        Ok(rows)
    }
    fn verify(&self, command: &str, args: &[&str], value: &Value) -> Result<String> {
        let dir = temp()?;
        let p = dir.0.join("evidence.json");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)?;
        serde_json::to_writer(&mut f, value)?;
        drop(f);
        let mut child = Command::new(&self.binary)
            .arg(command)
            .args(args)
            .arg(p)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(s) = child.try_wait()? {
                if !s.success() {
                    return Err("native verifier rejected evidence".into());
                }
                let mut out = String::new();
                child
                    .stdout
                    .take()
                    .ok_or("missing output")?
                    .read_to_string(&mut out)?;
                return Ok(out);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("native verifier timed out".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    pub fn verify_response(
        &self,
        r: &Response,
        file: &Path,
        operator: &str,
        ledger: &str,
        expected_op: &str,
    ) -> Result<Value> {
        pin(operator)?;
        pin(ledger)?;
        if r.status != 200 || r.body["response"]["context"]["op"] != expected_op {
            return Err("response status or operation mismatch".into());
        }
        let e = evidence(file)?;
        same(
            &r.body,
            &e,
            &[
                "result",
                "receipt",
                "response",
                "responseDecision",
                "responseEventRef",
            ],
        )?;
        self.verify(
            "verify-response",
            &["--operator-key", operator, "--ledger-key", ledger],
            &e,
        )?;
        Ok(
            json!({"verified":true,"scope":"historical response evidence","currentAuthorityVerified":false}),
        )
    }
    pub fn verify_failure(
        &self,
        r: &Response,
        file: &Path,
        operator: &str,
        ledger: &str,
    ) -> Result<Value> {
        pin(operator)?;
        pin(ledger)?;
        let mut core = r.body.as_object().ok_or("invalid response")?.clone();
        for k in [
            "failureCore",
            "failure",
            "failureDecision",
            "failureEventRef",
            "failureEvidenceFile",
            "proofStatus",
        ] {
            core.remove(k);
        }
        if r.body["proofStatus"] != "ledger-recorded"
            || Value::Object(core) != r.body["failureCore"]
        {
            return Err("failure response mismatch".into());
        }
        let e = evidence(file)?;
        same(
            &r.body,
            &e,
            &[
                "failureCore",
                "failure",
                "failureDecision",
                "failureEventRef",
                "error",
            ],
        )?;
        let digest = hex(&Sha256::digest(&r.request_bytes));
        if e["requestHash"] != digest || e["status"].as_u64() != Some(r.status as u64) {
            return Err("request or status mismatch".into());
        }
        self.verify(
            "verify-failure",
            &[
                "--operator-key",
                operator,
                "--ledger-key",
                ledger,
                "--request-hash",
                &digest,
                "--status",
                &r.status.to_string(),
            ],
            &e,
        )?;
        Ok(
            json!({"verified":true,"scope":"historical gateway observation","callerIdentityVerified":false,"effectStateVerified":false}),
        )
    }
    pub fn verify_ledger(&self, rows: &Value, ledger: &str) -> Result<Value> {
        pin(ledger)?;
        if !rows.is_array() {
            return Err("ledger rows required".into());
        }
        Ok(serde_json::from_str(&self.verify(
            "verify-ledger",
            &["--ledger-key", ledger],
            rows,
        )?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_pins_and_changed_evidence() {
        assert!(pin("bad").is_err());
        assert!(same(&json!({"x":1}), &json!({"x":2}), &["x"]).is_err());
        assert!(same(&json!({}), &json!({}), &["x"]).is_err());
    }
}
