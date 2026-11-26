use http6_proposed_sdk::PilotClient;
use serde_json::json;
use std::{env, path::Path};
fn proposal(op: &str, amount: &str) -> serde_json::Value {
    json!({"op":op,"audience":"wallet","resource":"merchant-payment","args":{"network":"regtest","recipient":"merchant-a","satoshis":amount},"holdSeconds":4})
}
fn main() -> http6_proposed_sdk::Result<()> {
    let a: Vec<String> = env::args().collect();
    if a.len() != 5 {
        return Err("state binary operator ledger required".into());
    }
    let state = Path::new(&a[1]);
    let c = PilotClient::attach(state, Path::new(&a[2]))?;
    let (operator, ledger) = (&a[3], &a[4]);
    let r = c.invoke(&proposal("rust-sdk-ok", "100"))?;
    assert_eq!(r.status, 200);
    let file = state.join(r.body["responseEvidenceFile"].as_str().unwrap());
    c.verify_response(&r, &file, operator, ledger, "rust-sdk-ok")?;
    assert!(c
        .verify_response(&r, &file, &"0".repeat(64), ledger, "rust-sdk-ok")
        .is_err());
    assert!(c
        .verify_response(&r, &file, operator, ledger, "different-op")
        .is_err());
    let mut changed = r.clone();
    changed.body["result"]["amount"] = json!(101);
    assert!(c
        .verify_response(&changed, &file, operator, ledger, "rust-sdk-ok")
        .is_err());
    let f = c.invoke(&proposal("rust-sdk-denied", "1100"))?;
    assert_eq!(f.status, 403);
    let file = state.join(f.body["failureEvidenceFile"].as_str().unwrap());
    c.verify_failure(&f, &file, operator, ledger)?;
    let mut changed = f.clone();
    changed.request_bytes = b"altered".to_vec();
    assert!(c.verify_failure(&changed, &file, operator, ledger).is_err());
    let m = c.invoke_raw(b"{invalid")?;
    assert_eq!(m.status, 400);
    c.verify_failure(
        &m,
        &state.join(m.body["failureEvidenceFile"].as_str().unwrap()),
        operator,
        ledger,
    )?;
    let mut rows = c.events()?;
    let v = c.verify_ledger(&rows, ledger)?;
    assert_eq!(v["verified"], true);
    assert_eq!(v["latestHeadVerified"], false);
    rows[0]["event"] = json!("ALTERED");
    assert!(c.verify_ledger(&rows, ledger).is_err());
    println!(
        "{}",
        json!({"language":"rust","success":true,"denied":true,"malformed":true,"tamperingRejected":true,"ledgerVerified":true})
    );
    Ok(())
}
