import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {join} from 'node:path';
import {canonical, Http6Error} from './index.mjs';

// Experimental process adapter for the existing newline-delimited WASIX guest API.
// This is not an isolation boundary or protected hardware key store.
class Guest {
  constructor(wasmer, file) {
    this.process=spawn(wasmer,['run','--no-tty','--disable-cache',file],{stdio:['pipe','pipe','ignore']});
    this.lines=createInterface({input:this.process.stdout,crlfDelay:Infinity});
    this.chain=Promise.resolve(); this.failed=null;
    this.process.on('error',e=>{this.failed=e;});
  }
  call(cmd, args={}) {
    const perform=()=>new Promise((resolve,reject)=>{
      if(this.failed || this.process.exitCode!==null || this.process.signalCode!==null){reject(new Http6Error('CIRCUIT_UNAVAILABLE'));return;}
      const frame=canonical({...args,cmd});
      if(Buffer.byteLength(frame)>262144){reject(new Http6Error('CIRCUIT_FRAME_TOO_LARGE'));return;}
      let timer;
      const done=(err,value)=>{clearTimeout(timer);this.lines.off('line',onLine);this.process.off('exit',onExit);this.process.off('error',onError);err?reject(err):resolve(value)};
      const onExit=()=>done(new Http6Error('CIRCUIT_EXITED'));
      const onError=()=>done(new Http6Error('CIRCUIT_IO_FAILED'));
      const onLine=line=>{
        try {if(Buffer.byteLength(line)>262144)throw Error();const reply=JSON.parse(line);if(reply.ok===true)done(null,reply.value);else done(new Http6Error('CIRCUIT_REJECTED',{reason:String(reply.error||'rejected')}));}
        catch {done(new Http6Error('CIRCUIT_INVALID_REPLY'));}
      };
      this.lines.once('line',onLine);this.process.once('exit',onExit);this.process.once('error',onError);
      timer=setTimeout(()=>{this.process.kill('SIGTERM');done(new Http6Error('CIRCUIT_TIMEOUT'));},15000);
      this.process.stdin.write(frame+'\n',e=>{if(e)onError();});
    });
    const result=this.chain.then(perform); this.chain=result.catch(()=>{});return result;
  }
  async close(){
    if(this.process.exitCode!==null||this.process.signalCode!==null)return;
    const p=this.process;const done=new Promise(resolve=>p.once('exit',resolve));
    p.stdin.end();let timer;try{await Promise.race([done,new Promise(resolve=>{timer=setTimeout(resolve,3000);})]);}finally{clearTimeout(timer);}
    if(p.exitCode===null&&p.signalCode===null){p.kill('SIGTERM');await done;}
    this.lines.close();
  }
}

/** Direct access to pilot WASIX guests. Caller supplies and owns authoritative trust and ledger registration. */
export class WasixCircuits {
  static async start({wasmer='wasmer',binDir}){
    if(!binDir)throw new Http6Error('WASIX_BIN_DIRECTORY_REQUIRED');
    const c=new WasixCircuits();c.wasmer=wasmer;c.binDir=binDir;c.children=new Map();
    c.birthQueue=Promise.resolve();c.mint=new Guest(wasmer,join(binDir,'mint.wasm'));c.verifier=new Guest(wasmer,join(binDir,'verifier.wasm'));
    try{c.mintIdentity=await c.mint.call('hello');c.verifierIdentity=await c.verifier.call('hello');return c;}
    catch(e){await c.close();throw e;}
  }
  identities(){return {mint:{...this.mintIdentity},verifier:{...this.verifierIdentity}};}
  async admitRoot({policy,manifest,originCert,operator,ledger,semantics,trust,registerRoot}){
    if(typeof registerRoot!=='function')throw new Http6Error('ROOT_LEDGER_REGISTRATION_REQUIRED');
    if(trust?.mint!==this.mintIdentity.issuer||trust?.verifier!==this.verifierIdentity.key)throw new Http6Error('CIRCUIT_TRUST_MISMATCH');
    const family=await this.mint.call('root',{policy,manifest,originCert,operator,ledger,semantics});
    await this.verifier.call('configure',{trust});
    await this.verifier.call('root',{family});
    // The caller must verify a durable ledger acknowledgement before returning.
    await registerRoot(family);
    this.trust=trust;this.rootFamily=family;return family;
  }
  mintChild(input){
    const pending=this.birthQueue.then(()=>this._mintChild(input));
    this.birthQueue=pending.catch(()=>{});return pending;
  }
  async _mintChild({birthId,holder,policy,registerFamily}){
    if(!this.trust||typeof registerFamily!=='function')throw new Http6Error('CONFIGURED_VERIFIER_AND_LEDGER_REGISTRATION_REQUIRED');
    if(this.children.has(holder))throw new Http6Error('CHILD_ALREADY_EXISTS');
    const child=new Guest(this.wasmer,join(this.binDir,'child.wasm'));
    try{
      const id=await child.call('hello');
      const terms=await this.mint.call('prepare-birth',{birthId,holder,childKey:id.key,policy});
      const joinToken=await child.call('join',{terms,policy});
      const birth=await this.mint.call('birth',{join:joinToken});
      await this.verifier.call('family',{family:birth.family});
      await registerFamily(birth.family);
      const provision={family:birth.family,privateProvision:birth.privateProvision};
      await this.verifier.call('enroll',provision);
      await child.call('activate',{...provision,trust:this.trust});
      // Provision remains in this host process and the guests; it is never returned or logged.
      this.children.set(holder,{guest:child,family:birth.family,queue:Promise.resolve()});
      return {holder,key:id.key,family:birth.family};
    }catch(e){await child.close();throw e;}
  }
  proveRequest(input){
    const child=this.children.get(input.holder);if(!child)throw new Http6Error('UNKNOWN_CHILD');
    const pending=child.queue.then(()=>this._proveRequest(input,child));
    child.queue=pending.catch(()=>{});return pending;
  }
  async _proveRequest({op,intent,holdSeconds=5},child){
    const attempt=await child.guest.call('prepare',{op,intent,holdSeconds});
    const challenge=await this.verifier.call('challenge',{intent,attempt});
    const witness=await child.guest.call('answer',challenge);
    const proof=await this.verifier.call('attest',{attempt,witness});
    return child.guest.call('request',{proof});
  }
  async verifyRequest({holder,package:pkg}){
    const child=this.children.get(holder);if(!child)throw new Http6Error('UNKNOWN_CHILD');
    return this.verifier.call('request',{family:child.family,package:pkg});
  }
  async close(){
    await Promise.allSettled([...(this.children?.values()||[])].map(x=>x.guest.close()));
    await Promise.allSettled([this.mint?.close(),this.verifier?.close()].filter(Boolean));
  }
}
