"""Synthetic local bridge between the review proof model and the WASIX pilot.

This adapter adds a separate, locally verified review proof around a real pilot
proposal and receipt. It does not make the profiles wire-compatible or replace
the pilot's resource-side policy and ledger checks.
"""
from __future__ import annotations
import copy
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
from review_channel import ReviewChannel


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__('localhost', timeout=10)
        self.socket_path = socket_path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def run_bridge(kit_path, state_dir, pilot_binary, operator_key, ledger_key):
    if not all(re.fullmatch(r'[0-9a-f]{64}', key) for key in (operator_key, ledger_key)):
        raise ValueError('independently enrolled operator and ledger keys are required')
    state = Path(state_dir).resolve()
    connections = json.loads((state / 'connections.json').read_text())
    proposal = {'op':'bridge-' + secrets.token_hex(8), 'audience':'wallet', 'resource':'merchant-payment',
                'args':{'network':'regtest','recipient':'merchant-a','satoshis':'250'},'holdSeconds':4}
    review = ReviewChannel(kit_path)
    try:
        # The complete proposal is part of the review request's authenticated statement.
        request_payload = {'operation':'read','resource':'/reports/approved',
                           'destination':'reports.example','body':{'pilotProposal':proposal}}
        request_proof = review.prepare_request(request_payload, proposal['op'])
        request_decision = review.validate_request_and_enforce(request_proof)
        if not request_decision.get('accepted'): raise RuntimeError('review request proof rejected')
        encoded = json.dumps(proposal,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
        connection = UnixConnection(connections['agent'])
        try:
            connection.request('POST','/http6/v0/propose',encoded,{'Content-Type':'application/json'})
            response = connection.getresponse()
            raw = response.read(65537)
            if len(raw)>65536: raise RuntimeError('pilot response exceeded limit')
            value = json.loads(raw)
            if response.status != 200: raise RuntimeError('pilot rejected proposal: '+str(value.get('error','unknown')))
        finally:
            connection.close()
        evidence_name=value.get('evidenceFile','')
        if not re.fullmatch(r'spend-[0-9a-f]{64}\.json',evidence_name): raise RuntimeError('invalid evidence file name')
        evidence=state/evidence_name
        verification=subprocess.run([str(pilot_binary),'verify-spend','--operator-key',operator_key,
            '--ledger-key',ledger_key,str(evidence)],check=True,capture_output=True,text=True,timeout=30)
        # The entire actual pilot JSON response is authenticated in the review response.
        response_payload={'operation':'respond','resource':'/reports/approved','destination':'client',
                          'body':{'pilotResponse':value}}
        response_proof=review.prepare_response(response_payload,request_decision['event'])
        changed=copy.deepcopy(response_proof)
        changed['statement']['payload']['body']['modified']=True
        try:
            rejected=review.validate_response(changed)
            if rejected.get('accepted'): raise RuntimeError('modified response was accepted')
        except review.kit.Rejected:
            pass
        response_decision=review.validate_response(response_proof)
        if not response_decision.get('accepted'): raise RuntimeError('review response proof rejected after pilot effect')
        return {'status':'PASS','operation':proposal['op'],
                'proposalDigest':hashlib.sha256(encoded).hexdigest(),
                'requestProof':'accepted','responseProof':'accepted','modifiedResponse':'rejected',
                'requestEvent':request_decision['event'],'responseEvent':response_decision['event'],
                'pilotReceiptVerification':verification.stdout.strip(),
                'pilotResponseDigest':hashlib.sha256(raw).hexdigest(),
                'evidenceFile':evidence_name,'reviewLedger':review.inspect(),
                'scope':'synthetic local bridge; separate review and WASIX trust and ledgers; no production interoperability'}
    finally:
        review.close()


def main():
    if len(sys.argv)!=6:
        raise SystemExit('Usage: python3 reference/pilot_bridge.py KIT_PATH STATE_DIR PILOT_BINARY OPERATOR_KEY LEDGER_KEY')
    print(json.dumps(run_bridge(*sys.argv[1:]),indent=2))

if __name__=='__main__': main()
