import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import Ajv2020 from 'ajv/dist/2020.js';
const load=async p=>JSON.parse(await readFile(new URL('../../../'+p,import.meta.url),'utf8'));

test('all proposed operations define bounded request and response schemas',async()=>{
 const spec=await load('static/artifacts/openapi.yaml');
 assert.equal(spec.openapi,'3.1.0');assert.match(spec.info.description,/read-only view of operations and schemas/);
 const names=new Set();
 for(const [path,item] of Object.entries(spec.paths)){
  assert.ok(item.post, path); const operation=item.post;
  assert.ok(operation.operationId && !names.has(operation.operationId));names.add(operation.operationId);
  assert.ok(operation.requestBody.required && operation.requestBody.content['application/json'].schema);
  for(const code of ['200','400','403','409','503'])assert.ok(operation.responses[code].content['application/json'].schema,`${path} ${code}`);
 }
 assert.equal(names.size,18);
 const visit=value=>{if(!value||typeof value!=='object')return;for(const [k,v] of Object.entries(value)){if(k==='$ref' && v.startsWith('#/components/schemas/'))assert.ok(spec.components.schemas[v.split('/').at(-1)],v);else visit(v)}};visit(spec);
 const ajv=new Ajv2020({strict:false});ajv.addSchema(spec,'urn:http6:guide');
 const vectors=await load('static/artifacts/synthetic-vectors.json');
 const validate=ajv.getSchema('urn:http6:guide#/components/schemas/ReservationRequest');
 assert.ok(validate(vectors.requestPacket),JSON.stringify(validate.errors));
 const ledger=ajv.getSchema('urn:http6:guide#/components/schemas/LedgerQueryResponse');
 const response={events:vectors.events,checkpoint:vectors.checkpoint,nextSequence:null};assert.ok(ledger(response),JSON.stringify(ledger.errors));
 const changed=structuredClone(response);changed.events[0].payload.kind='outcome';assert.equal(ledger(changed),false);
 assert.equal(ledger({...response,unexpected:true}),false);
});

test('WASIX ledger schema identifies proof events and rejects malformed digests',async()=>{
 const schema=await load('static/artifacts/wasix-ledger-02.schema.json');const validate=new Ajv2020({strict:false}).compile(schema);const hex='a'.repeat(64);
 const entry={v:'http6-wasix-delegation-02',kind:'ledger-entry',seq:2,prev:hex,event:'FAILURE_RESPONSE_PROVED',actor:'broker',op:'',channel:'denied',at:100,data:{failureProofRef:hex,failureContextRef:hex,failureChallengeRef:hex,requestHash:hex,resultHash:hex,category:'denied',status:403}};
 assert.ok(validate(entry),JSON.stringify(validate.errors));entry.data.status=400;assert.equal(validate(entry),false);entry.data.status=403;entry.data.requestHash='broken';assert.equal(validate(entry),false);
});


test('all pilot ledger event payloads are closed and unknown events are rejected',async()=>{
 const schema=await load('static/artifacts/wasix-ledger-02.schema.json');const validate=new Ajv2020({strict:false}).compile(schema);
 const fixtures=await load('packages/sdk/test/fixtures/ledger-payloads-02.json');
 assert.equal(fixtures.length,19);assert.equal(new Set(fixtures.map(x=>x.event)).size,19);
 for(const event of fixtures){
   assert.ok(validate(event),`${event.event}: ${JSON.stringify(validate.errors)}`);
   const extra=structuredClone(event);extra.data.unexpected='bad';assert.equal(validate(extra),false,event.event);
   const changed=structuredClone(event);delete changed.data[Object.keys(changed.data)[0]];assert.equal(validate(changed),false,event.event);
 }
 const unknown=structuredClone(fixtures[0]);unknown.event='UNKNOWN_EVENT';assert.equal(validate(unknown),false);
});
