import json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from http6_sdk import PilotClient, Response, VerificationError
state,binary,operator,ledger=sys.argv[1:]
c=PilotClient.attach(state,binary)
def proposal(op,amount):return {'op':op,'audience':'wallet','resource':'merchant-payment','args':{'network':'regtest','recipient':'merchant-a','satoshis':amount},'holdSeconds':4}
def rejects(fn):
 try:fn()
 except (VerificationError,ValueError):return
 raise AssertionError('expected rejection')
r=c.invoke(proposal('python-sdk-ok','100'));assert r.status==200
assert c.verify_response(r,Path(state)/r.body['responseEvidenceFile'],operator,ledger,'python-sdk-ok')['verified']
rejects(lambda:c.verify_response(r,Path(state)/r.body['responseEvidenceFile'],'0'*64,ledger,'python-sdk-ok'))
rejects(lambda:c.verify_response(r,Path(state)/r.body['responseEvidenceFile'],operator,ledger,'different-op'))
bad=json.loads(json.dumps(r.body));bad['result']['amount']=101
rejects(lambda:c.verify_response(Response(r.status,bad,r.request_bytes),Path(state)/r.body['responseEvidenceFile'],operator,ledger,'python-sdk-ok'))
f=c.invoke(proposal('python-sdk-denied','1100'));assert f.status==403
file=Path(state)/f.body['failureEvidenceFile'];assert c.verify_failure(f,file,operator,ledger)['verified']
rejects(lambda:c.verify_failure(Response(f.status,f.body,b'altered'),file,operator,ledger))
mal=c.invoke_raw(b'{invalid');assert mal.status==400
assert c.verify_failure(mal,Path(state)/mal.body['failureEvidenceFile'],operator,ledger)['verified']
rows=c.events();result=c.verify_ledger(rows,ledger);assert result['verified'] and not result['latestHeadVerified']
rows[0]['event']='ALTERED';rejects(lambda:c.verify_ledger(rows,ledger))
print(json.dumps({'language':'python','success':True,'denied':True,'malformed':True,'tamperingRejected':True,'ledgerVerified':True}))
