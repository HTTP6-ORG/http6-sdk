"""Exercise the compiled command-line entry points with fresh, private test state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "bin" / "http6-pilot"


def invoke(*args, success=True):
    result = subprocess.run([str(BINARY), *map(str, args)], capture_output=True, text=True, timeout=90)
    if success != (result.returncode == 0):
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout.strip() if success else result.stderr.strip()


def start(*args):
    return subprocess.Popen([str(BINARY), *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def wait_ready(process, marker):
    deadline = time.monotonic() + 25
    while not marker.exists():
        if process.poll() is not None or time.monotonic() > deadline:
            if process.poll() is None:
                process.terminate()
            raise RuntimeError(process.communicate(timeout=8)[0])
        time.sleep(0.05)


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    output, _ = process.communicate(timeout=12)
    if process.returncode:
        raise RuntimeError(output)


def private_agent(out):
    state = out / "private-agent"
    agent = start("agent", "--state", state)
    try:
        wait_ready(agent, state / "connections.json")
        connections = json.loads((state / "connections.json").read_text())
        for field in ("broker", "agent", "ledger"):
            path = Path(connections[field])
            assert path.is_socket() and path.stat().st_mode & 0o777 == 0o600
        trust = json.loads((state / "trust.json").read_text())
        assert set(trust["routes"]) == {"wallet", "process", "database"}
        assert {trust["ledger"], trust["localLedger"]} == {"http://local-ledger.local"}
        assert not (state / "ledger.sqlite").exists()
        base = {"op": "wallet-cli", "audience": "wallet", "resource": "merchant-payment", "holdSeconds": 4,
                "args": {"recipient": "merchant-a", "network": "regtest", "satoshis": "250"}}
        payload = json.dumps(base)
        reply = json.loads(invoke("request", "--state", state, payload))
        assert reply["result"]["amount"] == 250 and reply["result"]["recipient"] == "merchant-a"
        assert "SPENT" in invoke("request", "--state", state, payload, success=False)
        base["op"] = "over-limit"
        base["args"]["satoshis"] = "1100"
        assert "WALLET_AMOUNT_EXCEEDS_LIMIT" in invoke("request", "--state", state, json.dumps(base), success=False)
        assert "REJECTED" in invoke("request", "--state", state, json.dumps(base), success=False)
        proof_file = state / reply["evidenceFile"]
        with sqlite3.connect(state / "agent.sqlite") as db:
            decisions = [row[0] for row in db.execute("SELECT verdict FROM proposals ORDER BY id")]
            assert decisions == ["COMMITTED", "SPENT", "WALLET_AMOUNT_EXCEEDS_LIMIT", "REJECTED"]
        with sqlite3.connect(state / "broker.sqlite") as db:
            assert [r[0] for r in db.execute("SELECT decision FROM checks ORDER BY id")] == ["ELIGIBLE", "CONFIRMED"]
        with sqlite3.connect(state / "wallet.sqlite") as db:
            assert db.execute("SELECT sats FROM funds").fetchone() == (9750,)
            assert db.execute("SELECT count(*) FROM spends").fetchone() == (1,)
    finally:
        stop(agent)
    verified = invoke("verify-spend", "--operator-key", connections["operatorKey"],
                      "--ledger-key", connections["localLedgerKey"], proof_file)
    assert "OFFLINE VERIFIED 250" in verified
    response_file = state / reply["responseEvidenceFile"]
    response_args = ["verify-response", "--operator-key", connections["operatorKey"], "--ledger-key", connections["localLedgerKey"]]
    response_checked = invoke(*response_args, response_file)
    assert "RESPONSE VERIFIED" in response_checked
    with sqlite3.connect(state / "local-ledger.sqlite") as db:
        events = [row[0] for row in db.execute("SELECT event FROM events WHERE op='wallet-cli' ORDER BY seq")]
        assert events.count("RESPONSE_CHALLENGED") == events.count("RESPONSE_PROVED") == 1
        assert events.index("CUSTODIAN_OUTCOME") < events.index("RESPONSE_CHALLENGED") < events.index("RESPONSE_PROVED") < events.index("BROKER_CONFIRMED")
    with tempfile.TemporaryDirectory() as scratch:
        modified = json.loads(response_file.read_text())
        modified["result"]["amount"] = 251
        changed_file = Path(scratch) / "modified-response.json"
        changed_file.write_text(json.dumps(modified))
        assert invoke(*response_args, changed_file, success=False)
    refusal_file, = state.glob("refusal-*.json")
    args = ["verify-refusal", "--operator-key", connections["operatorKey"], "--ledger-key", connections["localLedgerKey"]]
    checked = json.loads(invoke(*args, refusal_file))
    assert checked["reason"]["requestedSatoshis"] == "1100" and checked["reason"]["maximumSatoshis"] == "1000"
    assert checked["holder"] == "wallet-worker" and checked["decision"] == "REJECTED"
    with sqlite3.connect(state / "local-ledger.sqlite") as db:
        rows = list(db.execute("SELECT event FROM events WHERE op='over-limit' ORDER BY seq"))
        assert rows == [("WALLET_PROPOSAL_RECORDED",), ("WALLET_PROPOSAL_REFUSED",)]
        assert db.execute("SELECT COUNT(*) FROM operations WHERE op='over-limit'").fetchone() == (0,)
    bundle = json.loads(refusal_file.read_text())
    import copy
    mutations = {}
    with tempfile.TemporaryDirectory() as scratch:
        for field in ("proposal", "refusal", "proposalEntry", "refusalEntry", "family", "controlProof"):
            edited = copy.deepcopy(bundle)
            if field == "family":
                edited[field]["policy"]["layers"][1]["rules"][0]["args"]["satoshis"] = "9999"
            elif field == "controlProof":
                edited[field]["result"]["policyHash"] = "0" * 64
            else:
                value = edited[field].split(".")
                value[2] = ("A" if value[2][0] != "A" else "B") + value[2][1:]
                edited[field] = ".".join(value)
            challenge = Path(scratch) / "challenge.json"
            challenge.write_text(json.dumps(edited))
            mutations[field] = invoke(*args, challenge, success=False)
    assert invoke("verify-refusal", "--operator-key", connections["operatorKey"], "--ledger-key", "00"*32, refusal_file, success=False)
    return {"signedRefusal":checked,"tamperResults":mutations,"localSocketMode": "0600", "tcpListenersConfigured": 0, "debited": 250, "remaining": 9750,
            "replay": "SPENT", "overLimit": "REJECTED", "brokerDecisions": ["ELIGIBLE", "CONFIRMED"],
            "offlineVerifier": verified, "responseVerifier": response_checked, "responseEvidence": str(response_file.relative_to(out)), "spendEvidence": str(proof_file.relative_to(out))}


def existing_runtime(out, tmp):
    live = tmp / "running"
    process = start("runtime", "--socket-dir", live)
    try:
        wait_ready(process, live / "builds.json")
        assert process.poll() is None
        run = out / "attached-run"
        output = invoke("demo", "--runtime", live, "--out", run)
        assert "AUDIT " in output
        audit = invoke("audit", run)
        summary = json.loads((run / "summary.json").read_text())
        assert summary["allPassed"]
        process.wait(timeout=10)
        return {"existingSupervisorPID": process.pid, "singleAttachmentClosed": process.returncode == 0,
                "checks": summary["tests"], "audited": audit, "chainHeads": summary["chainHeads"]}
    finally:
        stop(process)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--capture-public", action="store_true", help="capture public HTTP messages and selected verifier inputs")
    options = parser.parse_args()
    out = options.out.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="h6-") as temp:
        report = {"binarySHA256": hashlib.sha256(BINARY.read_bytes()).hexdigest()}
        for name, run in [("privateAgent", lambda: private_agent(out)), ("existingRuntime", lambda: existing_runtime(out, Path(temp)))]:
            if options.capture_public:
                trace = out / (name + "-messages")
                trace.mkdir(mode=0o700)
                os.environ["HTTP6_PILOT_REPORT_DIR"] = str(trace)
            report[name] = run()
    (out / "entrypoints.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
