"""Adapter for the existing Rosario-Wang review model, not the WASIX pilot protocol."""
from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
import sys


def load_review_kit(path):
    source = Path(path).resolve() / "http6_rosario_wang_demo.py"
    if not source.is_file():
        raise FileNotFoundError(f"Review kit module not found: {source}")
    spec = importlib.util.spec_from_file_location("http6_review_runtime", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ReviewChannel:
    """Owns a local synthetic human, root, child, verifier and SQLite ledger."""
    def __init__(self, kit_path, database=":memory:"):
        self.kit = load_review_kit(kit_path)
        self.runtime, human = self.kit.setup_runtime(database)
        self.admission, self.mint = self.kit.ignite_and_mint(self.runtime, human)
        self.request_binding = self.kit.Binding("worker-1", "reports.example", "application-channel", "c2s")
        self.response_binding = self.kit.Binding("reports.example", "worker-1", "application-channel", "s2c")

    def prepare_request(self, payload, operation_id):
        challenge = self.runtime.challenge(self.request_binding, payload, kind="REQUEST", operation_id=operation_id)
        return self.runtime.peers[self.request_binding.sender].respond(challenge, self.request_binding, payload)

    def validate_request_and_enforce(self, proof):
        return self.runtime.submit(proof, self.request_binding)

    def prepare_response(self, payload, request_event):
        challenge = self.runtime.challenge(self.response_binding, payload, kind="RESPONSE", request_ref=request_event)
        return self.runtime.peers[self.response_binding.sender].respond(challenge, self.response_binding, payload)

    def validate_response(self, proof):
        return self.runtime.submit(proof, self.response_binding)

    def inspect(self):
        return {"effects": self.runtime.ledger.effect_count(), "accepted_proofs": len(self.runtime.observer),
                "scope": "local synthetic review model, not WASIX ledger evidence"}

    def close(self):
        self.runtime.ledger.close()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 reference/review_channel.py /path/to/HTTP6_RosarioWang_Validation_Kit")
    c = ReviewChannel(sys.argv[1])
    try:
        request_payload = {"operation": "read", "resource": "/reports/approved", "destination": "reports.example", "body": {"report": 7}}
        request = c.prepare_request(request_payload, "read-7")
        accepted_request = c.validate_request_and_enforce(request)
        if not accepted_request["accepted"]: raise RuntimeError("request not accepted")
        response_payload = {"operation": "respond", "resource": "/reports/approved", "destination": "client", "body": {"report": 7, "status": "synthetic result"}}
        response = c.prepare_response(response_payload, accepted_request["event"])
        changed = copy.deepcopy(response)
        changed["statement"]["payload"]["body"]["report"] = 8
        try:
            tampered_result = c.validate_response(changed)
            if tampered_result.get("accepted"): raise RuntimeError("altered response accepted")
        except c.kit.Rejected:
            pass
        accepted_response = c.validate_response(response)
        if not accepted_response["accepted"]: raise RuntimeError("response not accepted")
        if c.validate_response(response).get("status") != "REPLAY": raise RuntimeError("replay accepted")
        print(json.dumps({"status":"PASS", "admission":c.admission["status"], "mint":c.mint["status"],
            "request":accepted_request["status"], "response":accepted_response["status"],
            "altered_response":"rejected", "response_replay":"rejected", **c.inspect(),
            "warning":"Synthetic local reference model; no real human approval, WASIX interoperability, TLS, or production deployment."}, indent=2))
    finally:
        c.close()

if __name__ == "__main__":
    main()
