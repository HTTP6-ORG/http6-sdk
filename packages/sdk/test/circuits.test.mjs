import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {WasixCircuits,canonical} from '../src/index.mjs';
const PROFILE=process.env.HTTP6_TEST_PROFILE || 'http6-wasix-delegation-00';
const sha=x=>createHash('sha256').update(x).digest('hex');
const digest=(label,value)=>sha(Buffer.concat([Buffer.from(PROFILE+'/'+label+'\0'),Buffer.from(canonical(value))]));
const b64=x=>Buffer.from(x).toString('base64url');

test('existing mint, child and verifier produce and check a native request proof', {skip:!process.env.HTTP6_WASIX_BIN,timeout:60000}, async()=>{
  const bin=process.env.HTTP6_WASIX_BIN; const c=await WasixCircuits.start({binDir:bin});
  try{
    const ids=c.identities(),{publicKey,privateKey}=generateKeyPairSync('ed25519');
    const operator=publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex');
    const signed=p=>{const head={alg:'Ed25519',kid:operator,typ:'http6-wasix-delegation+jws'};const input=b64(canonical(head))+'.'+b64(canonical(p));return input+'.'+sign(null,Buffer.from(input),privateKey).toString('base64url');};
    const mintBuild=sha(await readFile(join(bin,'mint.wasm'))),childBuild=sha(await readFile(join(bin,'child.wasm')));
    const ledger='http://local-ledger.local';
    const rule={action:'report.read',audience:'database',resource:'monthly-total',args:{period:'2026-10',project:'p7'},releaseTo:'reader-1'};
    const routes={database:{ledger,target:'http://database.local/http6/v0/operate',ledgerKey:'0'.repeat(64)}};
    const manifest={routes,profile:PROFILE};const semantics=digest('semantics',manifest);
    const layer={schema:'policy-1',tenant:'lab',purpose:'month-close',ttlSeconds:300,budget:{pool:'p7',limit:3,per:1,unit:'calls'},delegation:{maxBirths:1,maxDepth:1,survive:false},rules:[rule]};
    const policy={v:PROFILE,semanticsHash:semantics,layers:[layer]};
    const now=Math.floor(Date.now()/1000);
    const originCert=signed({v:PROFILE,kind:'certified-origin',key:ids.mint.origin,issuer:ids.mint.issuer,policyHash:digest('policy',policy),ledger,semantics,nonce:randomBytes(32).toString('hex'),mintBuild,childBuild,nbf:now-1,exp:now+300});
    const trust={operator,mint:ids.mint.issuer,verifier:ids.verifier.key,ledger,mintBuild,childBuild,semantics,manifest,routes};
    const registrations=[];
    const root=await c.admitRoot({policy,manifest,originCert,operator,ledger,semantics,trust,registerRoot:async family=>registrations.push(family)});
    const leaf={...layer,ttlSeconds:200,budget:{pool:'p7',limit:2,per:1,unit:'calls'},delegation:{maxBirths:0,maxDepth:0,survive:false}};
    const childPolicy={v:PROFILE,semanticsHash:semantics,layers:[layer,leaf]};
    const born=await c.mintChild({birthId:'birth-reader-1',holder:'reader-1',policy:childPolicy,registerFamily:async family=>registrations.push(family)});
    assert.equal(registrations.length,2);assert.equal(born.holder,'reader-1');
    const intent={...rule,v:PROFILE,tenant:'lab',purpose:'month-close',rootRef:sha(root.root),inputHash:sha(Buffer.alloc(0)),units:1};
    const pkg=await c.proveRequest({holder:'reader-1',op:'proof-1',intent});
    assert.equal(pkg.proof.result.verdict,'accepted');
    const verified=await c.verifyRequest({holder:'reader-1',package:pkg});assert.equal(verified.op,'proof-1');
    const parallel=await Promise.all(['parallel-a','parallel-b'].map(op=>c.proveRequest({holder:'reader-1',op,intent})));
    assert.notEqual(parallel[0].proof.result.challenge,parallel[1].proof.result.challenge);
    const changed=structuredClone(pkg);changed.body.intent.args.project='other';
    await assert.rejects(c.verifyRequest({holder:'reader-1',package:changed}));
  }finally{await c.close();}
});
