import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, readFile, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {PilotClient, Http6Error, canonical, verifyLedgerEvents} from '../src/index.mjs';

test('codec orders keys and rejects unsafe values', () => {
  assert.equal(canonical({b:2,a:['x',true]}),'{"a":["x",true],"b":2}');
  assert.throws(()=>canonical({x:NaN}));
  assert.throws(()=>canonical({x:'\n'}));
});

test('fixture mints, proves, enforces, and verifies signed ledger and spend evidence', {skip:!process.env.HTTP6_PILOT_BINARY, timeout:60000}, async () => {
  const root=await mkdtemp(join(tmpdir(),'sdk-pilot-')); const state=join(root,'state');
  let client;
  try {
    client=await PilotClient.startFixture({pilotBinary:process.env.HTTP6_PILOT_BINARY,stateDir:state,expectedProfile:process.env.HTTP6_TEST_PROFILE || 'http6-wasix-delegation-00'});
    const wrongProfile=client.profile==='http6-wasix-delegation-01'?'http6-wasix-delegation-00':'http6-wasix-delegation-01';
    await assert.rejects(PilotClient.attach({stateDir:state,expectedProfile:wrongProfile}),e=>e.code==='PROFILE_MISMATCH');
    assert.equal(client.capabilities().generalMinting,false);
    if(client.profile==='http6-wasix-delegation-00') await assert.rejects(client.verifyNativeResponseProof(), e=>e.code==='RESPONSE_NATIVE_PROOF_NOT_SUPPORTED_BY_WASIX_PILOT');
    const proposal={op:'sdk-wallet-1',audience:'wallet',resource:'merchant-payment',args:{network:'regtest',recipient:'merchant-a',satoshis:'250'},holdSeconds:4};
    const result=await client.invoke(proposal);
    assert.equal(typeof result.evidenceFile,'string');
    const spend=await client.verifySpend({evidenceFile:join(state,result.evidenceFile),operatorKey:client.connections.operatorKey,ledgerKey:client.connections.localLedgerKey});
    assert.equal(spend.verified,true);
    if(client.profile!=='http6-wasix-delegation-00') {
      const evidenceFile=join(state,result.responseEvidenceFile);
      const pins={operatorKey:client.connections.operatorKey,ledgerKey:client.connections.localLedgerKey};
      const verified=await client.verifyNativeResponseProof({response:result,evidenceFile,...pins});
      assert.equal(verified.verified,true);assert.equal(verified.currentAuthorityVerified,false);
      const altered=JSON.parse(await readFile(evidenceFile,'utf8'));altered.result.amount=251;
      const alteredFile=join(root,'tampered-response.json');await writeFile(alteredFile,JSON.stringify(altered));
      await assert.rejects(client.verifyNativeResponseProof({response:result,evidenceFile:alteredFile,...pins}));
      const modifiedResponse=structuredClone(result);modifiedResponse.result.amount=251;
      await assert.rejects(client.verifyNativeResponseProof({response:modifiedResponse,evidenceFile,...pins}), e=>e.code==='RESPONSE_EVIDENCE_MISMATCH');
      await assert.rejects(client.verifyNativeResponseProof({response:result,evidenceFile,operatorKey:pins.operatorKey,ledgerKey:'0'.repeat(64)}));
    }
    if (process.env.HTTP6_REVIEW_KIT) {
      const bridge=fileURLToPath(new URL('../../../reference/pilot_bridge.py',import.meta.url));
      const {stdout}=await promisify(execFile)('python3',[bridge,process.env.HTTP6_REVIEW_KIT,state,process.env.HTTP6_PILOT_BINARY,client.connections.operatorKey,client.connections.localLedgerKey],{timeout:30000});
      const joined=JSON.parse(stdout);assert.equal(joined.requestProof,'accepted');assert.equal(joined.responseProof,'accepted');assert.equal(joined.modifiedResponse,'rejected');
      assert.match(joined.pilotReceiptVerification,/OFFLINE VERIFIED/);
    }
    await assert.rejects(client.invoke(proposal), e=>e instanceof Http6Error && e.code==='SPENT');
    await assert.rejects(client.invoke({...proposal,op:'sdk-wallet-denied',args:{...proposal.args,recipient:'merchant-b'}}));
    if (client.profile==='http6-wasix-delegation-02') {
      const pins={operatorKey:client.connections.operatorKey,ledgerKey:client.connections.localLedgerKey};
      const cases=[Buffer.from('{bad'),Buffer.from(canonical({...proposal,op:'sdk-over-limit',args:{...proposal.args,satoshis:'1100'}}))];
      for (const bytes of cases) {
        let failure; try { await client.invokeRaw(bytes); assert.fail('failure expected'); } catch (e) { failure=e; }
        assert.equal(failure.detail.response.proofStatus,'ledger-recorded');
        const evidenceFile=join(state,failure.detail.response.failureEvidenceFile);
        const result=await client.verifyFailureResponse({error:failure,requestBytes:bytes,evidenceFile,...pins});
        assert.equal(result.verified,true); assert.equal(result.effectStateVerified,false); assert.equal(result.callerIdentityVerified,false);
        await assert.rejects(client.verifyFailureResponse({error:failure,requestBytes:Buffer.from('changed'),evidenceFile,...pins}));
        await assert.rejects(client.verifyFailureResponse({error:failure,requestBytes:bytes,evidenceFile,operatorKey:pins.operatorKey,ledgerKey:'0'.repeat(64)}));
        const altered=structuredClone(failure.detail.response); altered.category='changed';
        const forged=new Http6Error(failure.code,{status:failure.detail.status,response:altered});
        await assert.rejects(client.verifyFailureResponse({error:forged,requestBytes:bytes,evidenceFile,...pins}),e=>e.code==='FAILURE_RESPONSE_MISMATCH');
      }
    }
    const evidence=await client.events({pinnedLedgerKey:client.connections.localLedgerKey});
    assert.ok(evidence.verification.verifiedEntries>0);
    assert.equal(evidence.verification.latestHeadVerified,false);
    const modified=structuredClone(evidence.rows); modified[0].event='MODIFIED';
    assert.throws(()=>verifyLedgerEvents(modified,client.connections.localLedgerKey,client.profile),e=>e.code==='LEDGER_ROW_MISMATCH');
    assert.throws(()=>verifyLedgerEvents(evidence.rows,'0'.repeat(64),client.profile));
  } finally { if(client) await client.close(); await rm(root,{recursive:true,force:true}); }
});
