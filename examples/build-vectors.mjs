// Public, deterministic educational fixtures only. Never use these keys in production.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const dir = dirname(fileURLToPath(import.meta.url));
const P = 'http6-guide-01', T = 1800000000;
const sha = b => createHash('sha256').update(b).digest('hex');
function canon(x) {
  if (x === null || typeof x === 'boolean') return JSON.stringify(x);
  if (typeof x === 'number') {
    if (!Number.isSafeInteger(x) || x < 0 || x > 253402300799) throw Error('integer outside profile');
    return String(x);
  }
  if (typeof x === 'string') {
    if (!/^[\x20-\x7e]*$/.test(x)) throw Error('non-ASCII string');
    return JSON.stringify(x);
  }
  if (Array.isArray(x)) return '[' + x.map(canon).join(',') + ']';
  if (typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype) {
    const keys = Object.keys(x).sort();
    if (keys.some(k => !/^[\x20-\x7e]*$/.test(k))) throw Error('non-ASCII key');
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canon(x[k])).join(',') + '}';
  }
  throw Error('unsupported value');
}
const bytes = x => Buffer.from(canon(x), 'utf8');
const framed = (label, x) => Buffer.concat([Buffer.from(P + '/' + label + '\0', 'ascii'), bytes(x)]);
const H = (label, x) => sha(framed(label, x));
const ref = x => H('signed', x);
const o = (kind, fields) => ({v:P, kind, ...fields});
const names = ['human-key','root-key','child-key','issuer-key','appraiser-key','verifier-key','state-key','resource-key','keeper-key'];
const keys = Object.fromEntries(names.map(name => {
  const seed = createHash('sha256').update('PUBLIC TEST SEED ONLY/' + name).digest();
  const privateKey = createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
  const spki = createPublicKey(privateKey).export({format:'der',type:'spki'});
  return [name, {privateKey, publicHex:spki.subarray(-32).toString('hex')}];
}));
function signed(keyId,payload) {
  return {payload,signature:{alg:'Ed25519',keyId,value:sign(null,framed('signature',{alg:'Ed25519',keyId,payload}),keys[keyId].privateKey).toString('hex')}};
}
function verifySigned(s) {
  const k=keys[s.signature.keyId];
  return !!k && s.signature.alg==='Ed25519' && verify(null,framed('signature',{alg:s.signature.alg,keyId:s.signature.keyId,payload:s.payload}),createPublicKey(k.privateKey),Buffer.from(s.signature.value,'hex'));
}
const service='https://reports.example/operate';
const rule={action:'report-read',resource:'monthly-total',audience:'reports-db',releaseTo:'reader-1',args:{period:'2026-10',project:'p7'}};
const rootPolicy=o('policy',{id:'policy-root',tenant:'lab',purpose:'month-close',rules:[rule],unit:'credits',pool:'pool-p7',limit:10,per:6,maxDepth:1,survive:false});
const childPolicy=o('policy',{id:'policy-child',tenant:'lab',purpose:'month-close',rules:[rule],unit:'credits',pool:'pool-p7',limit:6,per:6,maxDepth:0,survive:false});
const rootTerms={id:'root-1',rootId:'root-1',parentGrantRef:null,origin:'human-1',holder:'root-worker',keyId:'root-key',gen:1,service,policyRef:H('policy',rootPolicy),depth:1,limit:10,per:6,epoch:1,nbf:T-10,exp:T+600};
const challenge = (id,purpose,contextRef,actorKeyId,recipient,i) => signed('verifier-key',o('challenge',{id,nonce:sha('PUBLIC FIXTURE NONCE '+id),purpose,contextRef,actorKeyId,recipient,iat:T+i,exp:T+i+30}));
const rootChallenge=challenge('root-challenge','root-approval',H('terms',rootTerms),'human-key','admission',0);
const approval=signed('human-key',o('approval',{challengeRef:ref(rootChallenge),subject:'human-1',termsRef:H('terms',rootTerms),nbf:T,exp:T+30}));
const rootJoinChallenge=challenge('root-join','join',H('terms',rootTerms),'root-key','admission',0);
const rootJoin=signed('root-key',o('join',{challengeRef:ref(rootJoinChallenge),holder:'root-worker',keyId:'root-key',gen:1,termsRef:H('terms',rootTerms),nbf:T,exp:T+30}));
const appraisal=(holder,keyId)=>signed('appraiser-key',o('appraisal',{holder,keyId,gen:1,service,appraisalPolicy:'appraisal-1',measurement:sha('fixture measurement '+holder),nbf:T-1,exp:T+300}));
const rootAppraisal=appraisal('root-worker','root-key');
const root=signed('issuer-key',o('grant',{terms:rootTerms,approvalRef:ref(approval),parentRequestRef:null,joinRef:ref(rootJoin),appraisalRef:ref(rootAppraisal)}));
const childTerms={id:'grant-child',rootId:'root-1',parentGrantRef:ref(root),origin:'human-1',holder:'reader-1',keyId:'child-key',gen:1,service,policyRef:H('policy',childPolicy),depth:0,limit:6,per:6,epoch:1,nbf:T,exp:T+300};
const childChallenge=challenge('child-join','join',H('terms',childTerms),'child-key','delegation',1);
const childJoin=signed('child-key',o('join',{challengeRef:ref(childChallenge),holder:'reader-1',keyId:'child-key',gen:1,termsRef:H('terms',childTerms),nbf:T+1,exp:T+31}));
const parentRequest=signed('root-key',o('parent-request',{parentGrantRef:ref(root),childTermsRef:H('terms',childTerms),joinRef:ref(childJoin),nbf:T+1,exp:T+31}));
const childAppraisal=appraisal('reader-1','child-key');
const child=signed('issuer-key',o('grant',{terms:childTerms,approvalRef:null,parentRequestRef:ref(parentRequest),joinRef:ref(childJoin),appraisalRef:ref(childAppraisal)}));
const input=Buffer.from('');
const intent=o('intent',{rootId:'root-1',tenant:'lab',purpose:'month-close',audience:'reports-db',action:'report-read',resource:'monthly-total',args:rule.args,inputHash:sha(input),releaseTo:'reader-1',units:6});
const attempt=o('attempt',{op:'op-42',record:'record-42',intentRef:H('intent',intent),grantRef:ref(child),policyRef:H('policy',childPolicy),holder:'reader-1',keyId:'child-key',gen:1,method:'POST',target:service,epoch:1,iat:T+2,exp:T+25});
const proof=(direction,ctx,actor,policy,i)=>{
  const c=challenge(direction+'-challenge',direction+'-proof',ctx,actor,direction==='request'?'resource':'client',i);
  // Synthetic verifier assertion only: this generator does not run a circuit.
  const result=signed('verifier-key',o('proof-result',{proofType:'designated-verifier-attestation',direction,contextRef:ctx,challengeRef:ref(c),actorKeyId:actor,policyRef:policy,witnessCommitment:sha('PUBLIC SIMULATED WITNESS '+direction),verdict:'accepted',iat:T+i,exp:T+i+20}));
  return {challenge:c,result};
};
const requestProof=proof('request',H('attempt',attempt),'child-key',childTerms.policyRef,3);
const request=signed('child-key',o('request',{attemptRef:H('attempt',attempt),proofRef:H('proof',requestProof)}));
const requestPacket={intent,input:input.toString('hex'),attempt,proof:requestProof,request,grantChain:[root,child],policies:[rootPolicy,childPolicy],appraisal:childAppraisal};
const permit=signed('state-key',o('permit',{id:'permit-42',op:'op-42',record:'record-42',intentRef:H('intent',intent),requestRef:ref(request),proofRef:H('proof',requestProof),grantRef:ref(child),policyRef:childTerms.policyRef,holder:'reader-1',keyId:'child-key',audience:'reports-db',units:6,epoch:1,fence:1,iat:T+4,exp:T+20}));
const presentationRef=H('request-packet',requestPacket);
const control=signed('resource-key',o('ledger-control',{action:'redeem',requestRef:ref(request),permitRef:ref(permit),presentationRef,caller:'reports-db',nonce:sha('PUBLIC FIXTURE CONTROL NONCE'),idempotencyKey:'redeem-42',iat:T+5,exp:T+20}));
const decision=signed('state-key',o('ledger-decision',{controlRef:ref(control),requestRef:ref(request),permitRef:ref(permit),caller:'reports-db',nonce:control.payload.nonce,decision:'redeemed',sequence:1,epoch:1,fence:1,iat:T+5,exp:T+20}));
const resultBytes=Buffer.from('{"total":42}','utf8');
const outcome=signed('resource-key',o('outcome',{op:'op-42',permitRef:ref(permit),requestRef:ref(request),intentRef:H('intent',intent),audience:'reports-db',row:'row-42',resultHash:sha(resultBytes),units:6,epoch:1,at:T+6}));
const responseContext=o('response-context',{op:'op-42',record:'response-42',requestRef:ref(request),recipientKeyId:'child-key',resourceKeyId:'resource-key',policyRef:childTerms.policyRef,status:200,contentType:'application/json',resultHash:sha(resultBytes),outcomeRef:ref(outcome),iat:T+6,exp:T+26});
const responseProof=proof('response',H('response-context',responseContext),'resource-key',childTerms.policyRef,7);
const response=signed('resource-key',o('response',{contextRef:H('response-context',responseContext),proofRef:H('proof',responseProof)}));
const responsePacket={context:responseContext,result:resultBytes.toString('hex'),proof:responseProof,outcome,response};
const event1=signed('state-key',o('ledger-event',{ledger:'ledger-1',sequence:1,prev:null,event:'redeemed',actor:'reports-db',op:'op-42',objectRef:ref(decision),at:T+5}));
const event2=signed('state-key',o('ledger-event',{ledger:'ledger-1',sequence:2,prev:ref(event1),event:'committed',actor:'reports-db',op:'op-42',objectRef:ref(outcome),at:T+6}));
const state={epoch:1,fence:1,rootId:'root-1',spent:6,reserved:0,revoked:false};
const checkpoint=signed('keeper-key',o('checkpoint',{ledger:'ledger-1',sequence:2,head:ref(event2),stateHash:H('state',state),epoch:1,at:T+8}));
const all=[rootChallenge,approval,rootJoinChallenge,rootJoin,rootAppraisal,root,childChallenge,childJoin,parentRequest,childAppraisal,child,requestProof.challenge,requestProof.result,request,permit,control,decision,outcome,responseProof.challenge,responseProof.result,response,event1,event2,checkpoint];
function check(b,m){if(!b)throw Error(m);}
all.forEach(x=>check(verifySigned(x),'signature '+x.payload.kind));
check(root.payload.terms.policyRef===H('policy',rootPolicy),'root policy');
check(child.payload.terms.parentGrantRef===ref(root) && child.payload.terms.policyRef===H('policy',childPolicy),'child binding');
check(parentRequest.payload.childTermsRef===H('terms',childTerms) && parentRequest.payload.joinRef===ref(childJoin),'child authorization');
check(attempt.intentRef===H('intent',intent) && request.payload.attemptRef===H('attempt',attempt) && request.payload.proofRef===H('proof',requestProof),'request binding');
check(requestProof.result.payload.challengeRef===ref(requestProof.challenge) && requestProof.result.payload.contextRef===H('attempt',attempt),'request proof binding');
check(permit.payload.requestRef===ref(request) && decision.payload.controlRef===ref(control) && decision.payload.nonce===control.payload.nonce,'state binding');
check(outcome.payload.resultHash===sha(resultBytes) && responseContext.outcomeRef===ref(outcome) && responseContext.requestRef===ref(request),'outcome binding');
check(response.payload.contextRef===H('response-context',responseContext) && response.payload.proofRef===H('proof',responseProof) && responseProof.result.payload.contextRef===H('response-context',responseContext),'response binding');
check(event2.payload.prev===ref(event1) && checkpoint.payload.head===ref(event2) && checkpoint.payload.stateHash===H('state',state),'ledger chain');
const tampered=structuredClone(request); tampered.payload.attemptRef='0'.repeat(64);
check(!verifySigned(tampered),'tampered signature unexpectedly valid');
check(sha(Buffer.from('{"total":43}'))!==responseContext.resultHash,'tampered response unexpectedly valid');
const output={notice:'Public synthetic fixture. Signatures are real Ed25519. Proof verdicts are simulated attestations, not circuit proofs, human approvals, ledger operations, or resource effects.',profile:P,time:T,publicKeys:Object.fromEntries(names.map(n=>[n,keys[n].publicHex])),rootPolicy,childPolicy,rootTerms,rootChallenge,approval,rootJoinChallenge,rootJoin,rootAppraisal,root,childTerms,childChallenge,childJoin,parentRequest,childAppraisal,child,inputHex:input.toString('hex'),requestPacket,permit,control,decision,responsePacket,events:[event1,event2],state,checkpoint,digests:{rootPolicy:rootTerms.policyRef,childPolicy:childTerms.policyRef,intent:H('intent',intent),attempt:H('attempt',attempt),requestProof:H('proof',requestProof),request:ref(request),requestPacket:presentationRef,permit:ref(permit),outcome:ref(outcome),responseContext:H('response-context',responseContext),responseProof:H('proof',responseProof),response:ref(response),responsePacket:H('response-packet',responsePacket),checkpoint:ref(checkpoint)}};
writeFileSync(join(dir,'synthetic-vectors.json'),JSON.stringify(output,null,2)+'\n');
console.log('PASS: 24 real Ed25519 fixture signatures and request, response, ledger digest links');
console.log('PASS: changed signed attempt reference and changed result bytes rejected by fixture checks');
console.log('NOTICE: circuit proofs, resource effect, ledger decisions and human approval are simulated');
