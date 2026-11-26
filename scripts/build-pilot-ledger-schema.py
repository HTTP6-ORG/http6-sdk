#!/usr/bin/env python3
"""Produce the syntactic WASIX 02 ledger schema from the pilot event contract."""
import json
from pathlib import Path
H={'type':'string','pattern':'^[0-9a-f]{64}$'}
S={'type':'string'}
N={'type':'integer','minimum':0}
J={'type':'string','pattern':r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'}
ST={'enum':['ISSUED','HELD','REDEEMED','COMMITTED','REJECTED','EXPIRED']}
CAT={'enum':['malformed','denied','held','uncertain']}
STATUS={'enum':[400,403,503]}
def obj(props, optional=()):return {'type':'object','additionalProperties':False,'properties':props,'required':[k for k in props if k not in optional]}
def hashes(*names):return {n:H for n in names}
base={**hashes('certificateRef','presentationRef','proofRef','requestRef','policyHash','controlProofRef','verifierNonce'),'proofVerified':{'const':True},'stateBefore':ST}
check=base|{'decision':{'enum':['ELIGIBLE','REJECTED','EXPIRED','SPENT','POLICY_DENIED','CHANNEL_MISMATCH','REVOKED']},'policyAllowed':{'type':'boolean'},'stateAfter':{'const':'REJECTED'}}
redeem=base|{'decision':{'const':'REDEEMED'},'policyAllowed':{'type':'boolean'},'redemptionId':H}
challenge=base|{'decision':{'const':'RESPONSE_CHALLENGED'},**hashes('responseContextRef','responseNonce','receiptRef')}
proved=base|{'decision':{'const':'RESPONSE_PROVED'},**hashes('responseProofRef','responseContextRef','responseChallengeRef','receiptRef','resultHash','responseNonce')}
record=hashes('proposalRef','proposalHash','agentKey','rootRef','originRef','grantRef','policyHash')|{'holder':S,'policyAddress':S}
reason=obj({'code':{'const':'WALLET_AMOUNT_EXCEEDS_LIMIT'},'requestedSatoshis':S,'maximumSatoshis':S,'recipient':S,'network':S})
contracts={
 'ROOT_ADMITTED':('mint',obj(hashes('grantRef','policyHash','rootRef'))),
 'CHILD_MINTED':('mint',obj(hashes('grantRef','policyHash','rootRef'))),
 'REQUEST_PROVED':('http6-agent',obj(hashes('intentRef','bodyRef','transcriptRef','proofRef','requestRef','policyHash','grantRef'))),
 'CERTIFICATE_ISSUED':('ledger',obj({'certificateRef':H,'exp':N})),
 'CHECKED':(None,obj(check,('policyAllowed','stateAfter'))),
 'REDEEMED':(None,obj(redeem)),
 'RECOVERED_REDEMPTION':(None,obj(redeem)),
 'DELIVERY_HELD':('broker',obj(base|{'decision':{'const':'HELD'},'deadline':N,'reason':{'const':'resource unavailable'}})),
 'DELIVERY_UNCERTAIN':('broker',obj(base|{'decision':{'const':'UNCERTAIN'},'reason':{'const':'resource response unavailable after redemption'}})),
 'RESPONSE_CHALLENGED':(None,obj(challenge)),
 'RESPONSE_PROVED':(None,obj(proved)),
 'CUSTODIAN_OUTCOME':(None,obj(base|{'decision':{'const':'COMMITTED'},'receiptRef':H})),
 'BROKER_CONFIRMED':('broker',obj(base|{'decision':{'const':'CONFIRMED'},**hashes('receiptRef','responseProofRef','responseEventRef')})),
 'GRANT_REVOKED':('operator',obj({'grantRef':H,'authorization':J})),
 'EXPIRED':('ledger',obj({'certificateRef':H,'stateBefore':{'enum':['ISSUED','HELD']},'deadline':{'type':'string','pattern':'^[0-9]+$'}})),
 'WALLET_PROPOSAL_RECORDED':('http6-agent',obj(record)),
 'WALLET_PROPOSAL_REFUSED':('broker',obj(record|hashes('brokerKey','brokerOriginRef','proposalEntryRef','refusalRef','controlProofRef')|{'decision':{'const':'REJECTED'},'reason':reason})),
 'FAILURE_RESPONSE_CHALLENGED':('broker',obj(hashes('failureContextRef','requestHash','resultHash')|{'status':STATUS})),
 'FAILURE_RESPONSE_PROVED':('broker',obj(hashes('failureProofRef','failureContextRef','failureChallengeRef','requestHash','resultHash')|{'category':CAT,'status':STATUS})),
}
# A failure category has one defined status in this profile.
failure_data=contracts['FAILURE_RESPONSE_PROVED'][1]
failure_data['allOf']=[{'if':{'properties':{'category':{'const':category}},'required':['category']},'then':{'properties':{'status':{'const':status}}}} for category,status in [('malformed',400),('denied',403),('held',503),('uncertain',503)]]
# The caller-specific event kind is closed. Signatures and relationships require additional verification.
entry=obj({'v':{'const':'http6-wasix-delegation-02'},'kind':{'const':'ledger-entry'},'seq':{'type':'integer','minimum':1},'prev':{'anyOf':[H,{'const':''}]},'event':{'enum':list(contracts)},'actor':S,'op':S,'channel':S,'data':{'type':'object'},'at':N})
entry['allOf']=[]
for name,(actor,data) in contracts.items():
 props={'data':data}
 if actor:props['actor']={'const':actor}
 entry['allOf'].append({'if':{'properties':{'event':{'const':name}},'required':['event']},'then':{'properties':props}})
row=obj({'seq':{'anyOf':[{'type':'integer','minimum':1},{'type':'string','pattern':'^[1-9][0-9]*$'}]},'event':{'enum':list(contracts)},'actor':S,'op':S,'channel':S,'data':S,'signature':J,'ref':H})
schema={'$schema':'https://json-schema.org/draft/2020-12/schema','title':'WASIX 02 pilot ledger event schemas','description':'Syntactic forms for all recorded event kinds. Verify compact signatures, row and decoded payload equality, hash chain, trust pins, event semantics and checkpoint freshness independently.','oneOf':[{'$ref':'#/$defs/row'},{'$ref':'#/$defs/entry'}],'$defs':{'row':row,'entry':entry}}
Path(__file__).resolve().parents[1].joinpath('static/artifacts/wasix-ledger-02.schema.json').write_text(json.dumps(schema,indent=2)+'\n')
