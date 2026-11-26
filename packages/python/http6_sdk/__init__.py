"""Experimental local HTTP6 WASIX 02 adapter, not a production security product."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
from dataclasses import dataclass

PROFILE = 'http6-wasix-delegation-02'
_HEX = re.compile(r'^[0-9a-f]{64}$')
_METADATA = {'failureCore','failure','failureDecision','failureEventRef','failureEvidenceFile','proofStatus'}
class VerificationError(ValueError): pass

@dataclass(frozen=True)
class Response:
    status: int
    body: dict
    request_bytes: bytes

def canonical(value):
    def check(v):
        if v is None or isinstance(v,bool): return
        if isinstance(v,int) and 0 <= v <= 9007199254740991: return
        if isinstance(v,str) and all(32 <= ord(c) <= 126 for c in v): return
        if isinstance(v,list):
            for x in v: check(x)
            return
        if isinstance(v,dict):
            for k,x in v.items():
                if not isinstance(k,str): raise TypeError('unsupported key')
                check(k); check(x)
            return
        raise TypeError('unsupported pilot JSON value')
    check(value)
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')

def _pins(*pins):
    if any(not isinstance(x,str) or not _HEX.fullmatch(x) for x in pins): raise VerificationError('valid independently configured trust pins required')

def _evidence(path):
    raw=Path(path).read_bytes()
    if len(raw)>10*1024*1024: raise VerificationError('evidence limit')
    v=json.loads(raw)
    if not isinstance(v,dict): raise VerificationError('invalid evidence')
    return v

class PilotClient:
    def __init__(self, agent_socket, ledger_socket, pilot_binary):
        self.agent_socket=str(agent_socket); self.ledger_socket=str(ledger_socket); self.pilot_binary=str(pilot_binary)
    @classmethod
    def attach(cls,state_dir,pilot_binary):
        c=json.loads((Path(state_dir)/'connections.json').read_text())
        if c.get('profile')!=PROFILE or not c.get('agent') or not c.get('ledger'): raise VerificationError('profile or connections mismatch')
        return cls(c['agent'],c['ledger'],pilot_binary)
    def _request(self,sock,method,path,body=None):
        class Local(http.client.HTTPConnection):
            def connect(self):
                self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15);self.sock.connect(sock)
        c=Local('agent.local',timeout=15)
        try:
            c.request(method,path,body,{'Content-Type':'application/json'} if body is not None else {})
            r=c.getresponse();raw=r.read(10*1024*1024+1)
            if len(raw)>10*1024*1024: raise VerificationError('response limit')
            return r.status,json.loads(raw)
        finally:c.close()
    def invoke(self,proposal): return self.invoke_raw(canonical(proposal))
    def invoke_raw(self,request_bytes):
        if not isinstance(request_bytes,bytes) or len(request_bytes)>65536: raise ValueError('bounded request bytes required')
        status,body=self._request(self.agent_socket,'POST','/http6/v0/propose',request_bytes)
        if not isinstance(body,dict): raise VerificationError('invalid response')
        return Response(status,body,request_bytes)
    def events(self):
        status,rows=self._request(self.ledger_socket,'GET','/http6/v0/events')
        if status!=200 or not isinstance(rows,list): raise VerificationError('ledger unavailable')
        return rows
    def _verify(self,command,args,value):
        with tempfile.TemporaryDirectory(prefix='http6-sdk-') as d:
            file=Path(d)/'evidence.json'
            fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f: json.dump(value,f,separators=(',',':'))
            p=subprocess.run([self.pilot_binary,command,*args,str(file)],capture_output=True,text=True,timeout=30)
            if p.returncode: raise VerificationError('native verifier rejected evidence')
            return p.stdout.strip()
    def verify_response(self,response,evidence_file,operator_key,ledger_key,expected_op):
        _pins(operator_key,ledger_key)
        b=response.body;e=_evidence(evidence_file)
        if response.status!=200 or b.get('response',{}).get('context',{}).get('op')!=expected_op: raise VerificationError('response status or operation mismatch')
        for k in ('result','receipt','response','responseDecision','responseEventRef'):
            if k not in b or b[k]!=e.get(k): raise VerificationError('response evidence mismatch')
        self._verify('verify-response',['--operator-key',operator_key,'--ledger-key',ledger_key],e)
        return {'verified':True,'scope':'historical response evidence','currentAuthorityVerified':False}
    def verify_failure(self,response,evidence_file,operator_key,ledger_key):
        _pins(operator_key,ledger_key)
        b=response.body;e=_evidence(evidence_file)
        if b.get('proofStatus')!='ledger-recorded' or {k:v for k,v in b.items() if k not in _METADATA}!=b.get('failureCore'): raise VerificationError('failure response mismatch')
        for k in ('failureCore','failure','failureDecision','failureEventRef','error'):
            if k not in b or b[k]!=e.get(k): raise VerificationError('failure evidence mismatch')
        digest=hashlib.sha256(response.request_bytes).hexdigest()
        if e.get('requestHash')!=digest or e.get('status')!=response.status: raise VerificationError('request or status mismatch')
        self._verify('verify-failure',['--operator-key',operator_key,'--ledger-key',ledger_key,'--request-hash',digest,'--status',str(response.status)],e)
        return {'verified':True,'scope':'historical gateway observation','callerIdentityVerified':False,'effectStateVerified':False}
    def verify_ledger(self,rows,ledger_key):
        _pins(ledger_key)
        if not isinstance(rows,list): raise VerificationError('ledger rows required')
        return json.loads(self._verify('verify-ledger',['--ledger-key',ledger_key],rows))
