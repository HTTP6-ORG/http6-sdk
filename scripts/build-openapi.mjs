import {readFile,writeFile} from 'node:fs/promises';
const schema=JSON.parse(await readFile(new URL('../static/artifacts/schema.json',import.meta.url),'utf8'));
const fix = value => JSON.parse(JSON.stringify(value).replaceAll('#/$defs/','#/components/schemas/'));
const schemas=fix(schema.$defs);
const ref=name=>({$ref:`#/components/schemas/${name}`});
const typed=(name,kind)=>schemas[name]={allOf:[ref('signed'),{properties:{payload:{properties:{kind:{const:kind}}}}}]};
for(const [name,kind] of Object.entries({SignedApproval:'approval',SignedJoin:'join',SignedAppraisal:'appraisal',SignedGrant:'grant',SignedParentRequest:'parent-request',SignedChallenge:'challenge',SignedProofResult:'proof-result',SignedPermit:'permit',SignedControl:'ledger-control',SignedDecision:'ledger-decision',SignedEvent:'ledger-event',SignedOutcome:'outcome',SignedClosure:'closure',SignedCheckpoint:'checkpoint',SignedRevocation:'revocation',SignedRecovery:'recovery'})) typed(name,kind);
const obj=properties=>({type:'object',additionalProperties:false,required:Object.keys(properties),properties});
const arr=(item,max=128)=>({type:'array',maxItems:max,items:ref(item)});
const str={type:'string',minLength:1,maxLength:256};
const integer={type:'integer',minimum:0,maximum:9007199254740991};
const nullable=name=>({oneOf:[ref(name),{type:'null'}]});
const pairs={
 RootChallenge:[obj({policy:ref('policy'),actorKeyId:ref('id'),recipient:ref('id')}),obj({challenge:ref('SignedChallenge')})],
 Admission:[obj({approval:ref('SignedApproval'),join:ref('SignedJoin'),appraisal:ref('SignedAppraisal'),policy:ref('policy')}),obj({grant:ref('SignedGrant'),event:ref('SignedEvent')})],
 ChildGrant:[obj({parentRequest:ref('SignedParentRequest'),join:ref('SignedJoin'),appraisal:ref('SignedAppraisal'),policy:ref('policy')}),obj({grant:ref('SignedGrant'),event:ref('SignedEvent')})],
 ProofChallenge:[obj({purpose:{enum:['request-proof','response-proof','ledger-control']},contextRef:ref('hash'),actorKeyId:ref('id'),recipient:ref('id')}),obj({challenge:ref('SignedChallenge')})],
 ProofVerify:[obj({proof:ref('proof'),contextRef:ref('hash')}),obj({result:ref('SignedProofResult')})],
 RequestMessage:[ref('requestPacket'),obj({result:ref('SignedProofResult')})],
 ResponseMessage:[ref('responsePacket'),obj({result:ref('SignedProofResult')})],
 Reservation:[ref('requestPacket'),obj({permit:ref('SignedPermit'),decision:ref('SignedDecision'),event:ref('SignedEvent')})],
 Check:[obj({control:ref('SignedControl'),permit:ref('SignedPermit'),proof:ref('proof')}),obj({decision:ref('SignedDecision'),event:ref('SignedEvent')})],
 Redemption:[obj({control:ref('SignedControl'),permit:ref('SignedPermit'),proof:ref('proof')}),obj({decision:ref('SignedDecision'),event:ref('SignedEvent')})],
 Outcome:[obj({control:ref('SignedControl'),outcome:ref('SignedOutcome')}),obj({decision:ref('SignedDecision'),event:ref('SignedEvent')})],
 Closure:[obj({control:ref('SignedControl'),closure:ref('SignedClosure')}),obj({decision:ref('SignedDecision'),event:ref('SignedEvent')})],
 Status:[obj({control:ref('SignedControl'),op:ref('id')}),obj({decision:ref('SignedDecision'),outcome:nullable('SignedOutcome'),closure:nullable('SignedClosure')})],
 LedgerQuery:[obj({control:ref('SignedControl'),afterSequence:integer,limit:{type:'integer',minimum:1,maximum:128}}),obj({events:arr('SignedEvent'),checkpoint:nullable('SignedCheckpoint'),nextSequence:{type:['integer','null'],minimum:0}})],
 Evidence:[obj({control:ref('SignedControl'),op:ref('id')}),obj({events:arr('SignedEvent'),checkpoint:nullable('SignedCheckpoint'),outcome:nullable('SignedOutcome'),closure:nullable('SignedClosure')})],
 Revocation:[obj({revocation:ref('SignedRevocation')}),obj({decision:ref('SignedDecision'),event:ref('SignedEvent')})],
 RecoveryPlan:[obj({control:ref('SignedControl'),checkpoint:ref('SignedCheckpoint')}),obj({recovery:ref('SignedRecovery'),event:ref('SignedEvent')})],
 RecoveryActivation:[obj({control:ref('SignedControl'),recovery:ref('SignedRecovery')}),obj({decision:ref('SignedDecision'),event:ref('SignedEvent')})],
};
for(const [name,[request,response]] of Object.entries(pairs)){schemas[name+'Request']=request;schemas[name+'Response']=response;}
schemas.ApiError=obj({code:{enum:['DENIED','MALFORMED','CONFLICT','HELD','UNCERTAIN','UNAVAILABLE']},message:str,requestId:ref('id')});
const specs=[
 ['/origins/challenges','prepareRootChallenge','Admission','RootChallenge'],['/origins/admissions','admitOrigin','Admission','Admission'],['/grants','mintChild','Minting','ChildGrant'],['/proofs/challenges','issueProofChallenge','Proofs','ProofChallenge'],['/proofs/verify','verifyNativeProof','Proofs','ProofVerify'],['/messages/requests/verify','verifyRequestMessage','Messages','RequestMessage'],['/messages/responses/verify','verifyResponseMessage','Messages','ResponseMessage'],['/operations/reservations','reserveOperation','Enforcement','Reservation'],['/operations/checks','checkOperation','Enforcement','Check'],['/operations/redemptions','redeemOperation','Enforcement','Redemption'],['/operations/outcomes','submitOutcome','Enforcement','Outcome'],['/operations/closures','submitClosure','Enforcement','Closure'],['/operations/status','inspectOperationStatus','Inspection','Status'],['/ledger/queries','inspectLedger','Inspection','LedgerQuery'],['/ledger/evidence-bundles','collectEvidence','Inspection','Evidence'],['/authority/revocations','revokeAuthority','Authority','Revocation'],['/authority/recovery-plans','planRecovery','Authority','RecoveryPlan'],['/authority/recovery-activations','activateRecovery','Authority','RecoveryActivation']];
const content=name=>({'application/json':{schema:ref(name)}});
const paths={};for(const [path,id,tag,name] of specs){paths[path]={post:{operationId:id,tags:[tag],summary:id.replace(/([A-Z])/g,' $1').replace(/^./,x=>x.toUpperCase()),requestBody:{required:true,content:content(name+'Request')},responses:{'200':{description:'Proposed signed result',content:content(name+'Response')},'400':{description:'Malformed',content:content('ApiError')},'403':{description:'Denied',content:content('ApiError')},'409':{description:'Conflict',content:content('ApiError')},'503':{description:'Held, uncertain or unavailable',content:content('ApiError')}}}};}
const api={openapi:'3.1.0',info:{title:'HTTP6 proposed guide API',version:'0.1.0-proposal',description:'http6-guide-01 API contract. The navigator provides a read-only view of operations and schemas.'},servers:[{url:'https://example.invalid/http6/api/v1',description:'Illustrative, non-routable'}],security:[{mutuallyAuthenticatedTransport:[]}],paths,components:{securitySchemes:{mutuallyAuthenticatedTransport:{type:'mutualTLS'}},schemas}};
await writeFile(new URL('../static/artifacts/openapi.yaml',import.meta.url),JSON.stringify(api,null,2)+'\n');
