import {createHash, createPublicKey, verify} from 'node:crypto';
import {request} from 'node:http';
import {spawn, execFile} from 'node:child_process';
import {readFile, stat, mkdtemp, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {promisify} from 'node:util';
import {join} from 'node:path';

const DEFAULT_PROFILE = 'http6-wasix-delegation-00';
const FAILURE_PROFILE = 'http6-wasix-delegation-02';
const SUPPORTED_PROFILES = new Set([DEFAULT_PROFILE, 'http6-wasix-delegation-01', FAILURE_PROFILE]);
const hasResponseProof = profile => profile === 'http6-wasix-delegation-01' || profile === FAILURE_PROFILE;
const execFileAsync = promisify(execFile);
const hash = b => createHash('sha256').update(b).digest('hex');
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const validKey = key => typeof key === 'string' && /^[0-9a-f]{64}$/.test(key);
const validRef = ref => typeof ref === 'string' && /^[0-9a-f]{64}$/.test(ref);

// This codec covers the pilot's restricted synthetic JSON vocabulary.
export function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value === 'string' && /^[\x20-\x7e]*$/.test(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(k => {
      if (!/^[\x20-\x7e]*$/.test(k)) throw new TypeError('Unsupported object key');
      return JSON.stringify(k) + ':' + canonical(value[k]);
    }).join(',') + '}';
  }
  throw new TypeError('Unsupported pilot JSON value');
}

export class Http6Error extends Error {
  constructor(code, detail = {}) { super(code); this.name = 'Http6Error'; this.code = code; this.detail = detail; }
}

function localRequest(socketPath, method, path, body, timeoutMs = 10000) {
  const encoded = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(canonical(body));
  if (encoded && encoded.length > 65536) throw new Http6Error('BODY_LIMIT');
  return new Promise((resolve, reject) => {
    const req = request({socketPath, method, path, headers: encoded ? {'content-type':'application/json', 'content-length':encoded.length} : {}}, res => {
      const chunks = []; let count = 0;
      res.on('data', chunk => {
        count += chunk.length;
        if (count > 10 * 1024 * 1024) { req.destroy(new Http6Error('RESPONSE_LIMIT')); return; }
        chunks.push(chunk);
      });
      res.on('end', () => {
        let value;
        try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch { reject(new Http6Error('INVALID_PILOT_RESPONSE')); return; }
        if (res.statusCode < 200 || res.statusCode >= 300) reject(new Http6Error(value?.error || 'PILOT_REJECTED', {status:res.statusCode, response:value}));
        else resolve(value);
      });
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Http6Error('TRANSPORT_TIMEOUT', {effect:'unknown'})));
    req.on('error', reject);
    req.end(encoded);
  });
}

function readJws(token, expectedKey, profile) {
  if (!validKey(expectedKey) || typeof token !== 'string' || token.length > 8192) throw new Http6Error('INVALID_LEDGER_ENTRY');
  const p = token.split('.');
  if (p.length !== 3 || p.some(x => !/^[A-Za-z0-9_-]+$/.test(x))) throw new Http6Error('INVALID_LEDGER_ENTRY');
  const hb=Buffer.from(p[0],'base64url'), pb=Buffer.from(p[1],'base64url'), sb=Buffer.from(p[2],'base64url');
  if (hb.toString('base64url')!==p[0] || pb.toString('base64url')!==p[1] || sb.toString('base64url')!==p[2] || sb.length!==64) throw new Http6Error('INVALID_LEDGER_ENTRY');
  let header, payload;
  try { header=JSON.parse(hb); payload=JSON.parse(pb); } catch { throw new Http6Error('INVALID_LEDGER_ENTRY'); }
  const expectedHeader={alg:'Ed25519',kid:expectedKey,typ:'http6-wasix-delegation+jws'};
  if (hb.toString()!==canonical(expectedHeader) || pb.toString()!==canonical(payload) || payload.v!==profile || payload.kind!=='ledger-entry') throw new Http6Error('INVALID_LEDGER_ENTRY');
  const pub=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(expectedKey,'hex')]),format:'der',type:'spki'});
  if (!verify(null,Buffer.from(p[0]+'.'+p[1]),pub,sb)) throw new Http6Error('INVALID_LEDGER_SIGNATURE');
  return payload;
}

/** Verify all returned event rows and their chain under an independently pinned key.
 * This cannot establish that the server returned its latest head, or prove an effect. */
export function verifyLedgerEvents(rows, pinnedLedgerKey, profile = DEFAULT_PROFILE) {
  if (!Array.isArray(rows) || !validKey(pinnedLedgerKey)) throw new Http6Error('TRUST_PIN_REQUIRED');
  if (!SUPPORTED_PROFILES.has(profile)) throw new Http6Error('UNSUPPORTED_PROFILE');
  let previous=''; let sequence=0;
  for (const row of rows) {
    const entry=readJws(row.signature,pinnedLedgerKey,profile);
    if (entry.seq!==sequence+1 || entry.prev!==previous || hash(Buffer.from(row.signature))!==row.ref || String(entry.seq)!==String(row.seq)) throw new Http6Error('LEDGER_CHAIN_MISMATCH');
    let data; try { data=JSON.parse(row.data); } catch { throw new Http6Error('LEDGER_ROW_MISMATCH'); }
    for (const k of ['actor','channel','event','op']) if (entry[k]!==row[k]) throw new Http6Error('LEDGER_ROW_MISMATCH');
    if (canonical(entry.data)!==canonical(data)) throw new Http6Error('LEDGER_ROW_MISMATCH');
    sequence=entry.seq; previous=row.ref;
  }
  return {profile, verifiedEntries:sequence, head:previous || null, latestHeadVerified:false, resourceEffectsVerified:false};
}

export class PilotClient {
  constructor(connections, options = {}) {
    if (!connections?.agent || !connections?.ledger) throw new Http6Error('INVALID_CONNECTIONS');
    this.connections=connections; this.pilotBinary=options.pilotBinary; this.child=options.child;
    this.profile=connections.profile || DEFAULT_PROFILE;
    if (!SUPPORTED_PROFILES.has(this.profile)) throw new Http6Error('UNSUPPORTED_PROFILE');
  }
  static async attach({stateDir, pilotBinary, expectedProfile=DEFAULT_PROFILE}) {
    if (!SUPPORTED_PROFILES.has(expectedProfile)) throw new Http6Error('UNSUPPORTED_PROFILE');
    const connections=JSON.parse(await readFile(join(stateDir,'connections.json'),'utf8'));
    if ((connections.profile || DEFAULT_PROFILE)!==expectedProfile) throw new Http6Error('PROFILE_MISMATCH');
    return new PilotClient(connections,{pilotBinary});
  }
  static async startFixture({pilotBinary, stateDir, expectedProfile=DEFAULT_PROFILE, timeoutMs=30000}) {
    if (!pilotBinary || !stateDir) throw new Http6Error('PILOT_BINARY_AND_NEW_STATE_REQUIRED');
    try { await stat(stateDir); throw new Http6Error('STATE_DIRECTORY_ALREADY_EXISTS'); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
    const child=spawn(pilotBinary,['agent','--state',stateDir],{stdio:['ignore','pipe','pipe']});
    let output='', failure;
    child.stdout.on('data', b=>{output=(output+b.toString()).slice(-8192)});
    child.stderr.on('data', b=>{output=(output+b.toString()).slice(-8192)});
    child.on('error', e=>{failure=e});
    const deadline=Date.now()+timeoutMs;
    while (Date.now()<deadline) {
      if (failure || child.exitCode!==null || child.signalCode!==null) throw new Http6Error('PILOT_START_FAILED',{message:failure?.message,output});
      if (output.includes('READY local agent ')) {
        try {
          const client=await PilotClient.attach({stateDir,pilotBinary,expectedProfile}); client.child=child; return client;
        } catch (e) {
          const ended=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGTERM');
          await Promise.race([ended,wait(10000)]);throw e;
        }
      }
      await wait(100);
    }
    child.kill('SIGTERM'); throw new Http6Error('PILOT_START_TIMEOUT',{output});
  }
  capabilities() {
    return {profile:this.profile, runtime:'synthetic autonomous pilot fixture', admission:'fixture bootstrap only', minting:'fixture children minted at startup', requestProof:'native designated verifier in pilot', enforcement:'registered pilot adapters only', ledger:'local socket', signedOutcome:'pilot receipt', responseNativeProof:hasResponseProof(this.profile), failureNativeProof:this.profile===FAILURE_PROFILE, humanApproval:false, generalMinting:false, productionReady:false};
  }
  async invoke(proposal) {
    const keys=Object.keys(proposal||{});
    if (this.profile !== FAILURE_PROFILE && keys.some(k=>!['op','audience','resource','args','holdSeconds'].includes(k))) throw new Http6Error('UNKNOWN_PROPOSAL_FIELD');
    return localRequest(this.connections.agent,'POST','/http6/v0/propose',proposal);
  }
  async invokeRaw(bytes) {
    if (this.profile !== FAILURE_PROFILE || !Buffer.isBuffer(bytes)) throw new Http6Error('RAW_REQUEST_REQUIRES_FAILURE_PROFILE_AND_BUFFER');
    return localRequest(this.connections.agent,'POST','/http6/v0/propose',bytes);
  }
  async catalog() { return localRequest(this.connections.ledger,'GET','/http6/v0/catalog'); }
  async events({pinnedLedgerKey}) {
    if (!validKey(pinnedLedgerKey)) throw new Http6Error('TRUST_PIN_REQUIRED');
    const rows=await localRequest(this.connections.ledger,'GET','/http6/v0/events');
    return {rows, verification:verifyLedgerEvents(rows,pinnedLedgerKey,this.profile)};
  }
  async resolve(kind, ref) {
    if (!['roots','policies','objects','families'].includes(kind) || !validRef(ref)) throw new Http6Error('INVALID_LEDGER_LOOKUP');
    // Returned objects require their own kind-specific verification under configured trust.
    return localRequest(this.connections.ledger,'GET',`/http6/v0/${kind}/${ref}`);
  }
  async verifySpend({evidenceFile, operatorKey, ledgerKey}) {
    if (!this.pilotBinary || !validKey(operatorKey) || !validKey(ledgerKey)) throw new Http6Error('VERIFIER_AND_TRUST_PINS_REQUIRED');
    const {stdout}=await execFileAsync(this.pilotBinary,['verify-spend','--operator-key',operatorKey,'--ledger-key',ledgerKey,evidenceFile],{timeout:30000,maxBuffer:65536});
    return {verified:true,scope:'historical synthetic pilot wallet evidence',output:stdout.trim(),responseNativeProof:hasResponseProof(this.profile)};
  }
  async verifyNativeResponseProof({response, evidenceFile, operatorKey, ledgerKey} = {}) {
    if (!hasResponseProof(this.profile)) throw new Http6Error('RESPONSE_NATIVE_PROOF_NOT_SUPPORTED_BY_WASIX_PILOT');
    if (!this.pilotBinary || !evidenceFile || !validKey(operatorKey) || !validKey(ledgerKey)) throw new Http6Error('VERIFIER_AND_TRUST_PINS_REQUIRED');
    if (!response || typeof response !== 'object') throw new Http6Error('ORIGINAL_RESPONSE_REQUIRED');
    const evidence = JSON.parse(await readFile(evidenceFile,'utf8'));
    for (const field of ['result','receipt','response','responseDecision','responseEventRef']) {
      if (response[field] === undefined || canonical(response[field]) !== canonical(evidence[field])) throw new Http6Error('RESPONSE_EVIDENCE_MISMATCH');
    }
    const privateDir=await mkdtemp(join(tmpdir(),'http6-response-'));
    try {
      const verifiedCopy=join(privateDir,'evidence.json');
      await writeFile(verifiedCopy,JSON.stringify(evidence),{mode:0o600});
      const {stdout}=await execFileAsync(this.pilotBinary,['verify-response','--operator-key',operatorKey,'--ledger-key',ledgerKey,verifiedCopy],{timeout:30000,maxBuffer:65536});
      return {verified:true,profile:this.profile,scope:'historical native response proof and signed ledger evidence',currentAuthorityVerified:false,output:stdout.trim()};
    } finally { await rm(privateDir,{recursive:true,force:true}); }
  }
  async verifyFailureResponse({error, requestBytes, evidenceFile, operatorKey, ledgerKey} = {}) {
    if (this.profile !== FAILURE_PROFILE) throw new Http6Error('FAILURE_NATIVE_PROOF_NOT_SUPPORTED');
    if (!this.pilotBinary || !evidenceFile || !validKey(operatorKey) || !validKey(ledgerKey)) throw new Http6Error('VERIFIER_AND_TRUST_PINS_REQUIRED');
    if (!(error instanceof Http6Error) || !Buffer.isBuffer(requestBytes)) throw new Http6Error('ORIGINAL_FAILURE_AND_REQUEST_BYTES_REQUIRED');
    const response=error.detail?.response, status=error.detail?.status;
    if (!response || response.proofStatus !== 'ledger-recorded' || response.error !== error.code) throw new Http6Error('FAILURE_PROOF_UNAVAILABLE');
    const core={...response};
    for (const field of ['failureCore','failure','failureDecision','failureEventRef','failureEvidenceFile','proofStatus']) delete core[field];
    if (canonical(core)!==canonical(response.failureCore)) throw new Http6Error('FAILURE_RESPONSE_MISMATCH');
    const evidence=JSON.parse(await readFile(evidenceFile,'utf8'));
    for (const field of ['failureCore','failure','failureDecision','failureEventRef','error']) {
      if (response[field] === undefined || canonical(response[field]) !== canonical(evidence[field])) throw new Http6Error('FAILURE_EVIDENCE_MISMATCH');
    }
    const requestHash=hash(requestBytes);
    if (evidence.requestHash!==requestHash || evidence.status!==status) throw new Http6Error('FAILURE_REQUEST_MISMATCH');
    const privateDir=await mkdtemp(join(tmpdir(),'http6-failure-'));
    try {
      const verifiedCopy=join(privateDir,'evidence.json');
      await writeFile(verifiedCopy,JSON.stringify(evidence),{mode:0o600});
      const {stdout}=await execFileAsync(this.pilotBinary,['verify-failure','--operator-key',operatorKey,'--ledger-key',ledgerKey,'--request-hash',requestHash,'--status',String(status),verifiedCopy],{timeout:30000,maxBuffer:65536});
      return {verified:true,profile:this.profile,scope:'historical gateway observation',callerIdentityVerified:false,effectStateVerified:false,output:stdout.trim()};
    } finally { await rm(privateDir,{recursive:true,force:true}); }
  }
  mintChild() { throw new Http6Error('ARBITRARY_MINTING_NOT_EXPOSED_BY_WASIX_PILOT_AGENT'); }
  async close() {
    if (!this.child || this.child.exitCode!==null || this.child.signalCode!==null) return;
    const child=this.child;
    const ended=new Promise(resolve=>child.once('exit',resolve));
    child.kill('SIGTERM');
    let timer;
    try { await Promise.race([ended,new Promise(resolve=>{timer=setTimeout(resolve,10000);})]); }
    finally { clearTimeout(timer); }
    if (child.exitCode===null && child.signalCode===null) throw new Http6Error('PILOT_SHUTDOWN_TIMEOUT');
  }
}

export {WasixCircuits} from './circuits.mjs';
