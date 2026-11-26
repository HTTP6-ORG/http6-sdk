#!/usr/bin/env python3
"""Synthetic local integration; retains only the new output directory supplied by the caller."""
import argparse, hashlib, http.client, json, os, pathlib, re, shutil, signal, socket, sqlite3, subprocess, sys, time

ROOT=pathlib.Path(__file__).resolve().parents[2]
def run(args, **kw):
    return subprocess.run([str(x) for x in args],check=True,capture_output=True,text=True,timeout=90,**kw).stdout.strip()
def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
def proposal(op,mode):return {'op':op,'audience':'wallet','resource':'merchant-payment','args':{'network':'regtest','recipient':'merchant-a','satoshis':'100' if mode=='allowed' else '1100'},'holdSeconds':4}
def pin_check(binary,state,reply,raw,status,config):
    b=reply['body']; pins=['--operator-key',config['operatorKey'],'--ledger-key',config['localLedgerKey']]
    if status==200:
        bundle=json.loads((state/b['responseEvidenceFile']).read_text())
        for key in ('result','receipt','response','responseDecision','responseEventRef'):
            assert b[key]==bundle[key],key
        assert 'RESPONSE VERIFIED' in run([binary,'verify-response',*pins,state/b['responseEvidenceFile']])
    else:
        assert b['proofStatus']=='ledger-recorded' and b['category']=='denied'
        bundle=json.loads((state/b['failureEvidenceFile']).read_text())
        for key in ('failure','failureCore','failureDecision','failureEventRef','error'):
            assert b[key]==bundle[key],key
        digest=hashlib.sha256(raw).hexdigest()
        assert bundle['requestHash']==digest and bundle['status']==status
        assert 'FAILURE VERIFIED' in run([binary,'verify-failure',*pins,'--request-hash',digest,'--status',str(status),state/b['failureEvidenceFile']])
        wrong=subprocess.run([str(binary),'verify-failure',*pins,'--request-hash','0'*64,'--status',str(status),str(state/b['failureEvidenceFile'])],capture_output=True,text=True,timeout=30)
        assert wrong.returncode!=0,'modified request digest accepted'
def post_raw(path,raw):
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(20);self.sock.connect(path)
    c=Local('agent.local',timeout=20)
    try:
        c.request('POST','/http6/v0/propose',raw,{'Content-Type':'application/json'});r=c.getresponse();return {'status':r.status,'body':json.loads(r.read())}
    finally:c.close()
def main():
    p=argparse.ArgumentParser();p.add_argument('--pilot',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--dotnet',default='dotnet');p.add_argument('--wasmer',default='wasmer');a=p.parse_args()
    binary=a.pilot.resolve(strict=True);out=a.out.resolve();out.mkdir(mode=0o700,parents=False,exist_ok=False);build=out/'build';build.mkdir(mode=0o700)
    env=os.environ.copy();env['DOTNET_CLI_HOME']=str(build/'dotnet-home');env['DOTNET_NOLOGO']='1';env['DOTNET_SKIP_FIRST_TIME_EXPERIENCE']='1';env['DOTNET_CLI_TELEMETRY_OPTOUT']='1';env['GOCACHE']=str(build/'go-cache')
    lang=ROOT/'examples/languages';rust=build/'rust-client';go=build/'go-client';cs=build/'csharp-source';cs.mkdir()
    shutil.copy(lang/'csharp/Program.cs',cs);shutil.copy(lang/'csharp/Client.csproj',cs)
    run(['rustc',lang/'rust/client.rs','-o',rust],env=env);run(['go','build','-o',go,lang/'go/client.go'],env=env);run([a.dotnet,'build',cs/'Client.csproj','-c','Release','-o',build/'csharp','--nologo'],env=env)
    commands={'node':['node',lang/'node/client.mjs'],'python':[sys.executable,lang/'python/client.py'],'rust':[rust],'go':[go],'csharp':[a.dotnet,build/'csharp/Client.dll']}
    report={'profile':'http6-wasix-delegation-02','scope':'synthetic local fixtures, ephemeral local trust pins, not production or independent operator verification','languages':{},'pythonWasix':{}}
    for language,cmd in commands.items():
        state=out/language;proc=subprocess.Popen([str(binary),'agent','--state',str(state)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(300):
                if (state/'connections.json').exists():break
                if proc.poll() is not None:raise RuntimeError('agent exited: '+proc.stderr.read())
                time.sleep(.1)
            else:raise RuntimeError('agent startup timeout')
            cfg=json.loads((state/'connections.json').read_text());assert cfg['profile']==report['profile']
            for mode,status in [('allowed',200),('denied',403)]:
                op=f'{language}-{mode}';raw=canonical(proposal(op,mode))
                result=json.loads(run([*cmd,cfg['agent'],op,mode],env=env));assert result['status']==status,(language,mode,result['status'])
                pin_check(binary,state,result,raw,status,cfg)
            if language=='python':
                # Python runs as a WASIX guest and synthesizes the exact bytes consumed by the Rust WASIX circuit path.
                cross=proposal('python-wasix-denied','denied');script=(ROOT/'examples/cross-runtime/python_guest.py').read_text()
                guest=json.loads(run([a.wasmer,'run','python/python@=3.13.18','--','-c',script],input=json.dumps(cross),env=env))
                raw=guest['body'].encode();assert raw==canonical(cross) and guest['sha256']==hashlib.sha256(raw).hexdigest()
                result=post_raw(cfg['agent'],raw);assert result['status']==403;pin_check(binary,state,result,raw,403,cfg)
                assert result['body']['failure']['context']['requestHash']==guest['sha256']
                report['pythonWasix']={'runtime':'python/python@=3.13.18 on Wasmer','result':'passed','requestBytesBoundToRustWasixFailureProof':True,'identityOrEffectVerified':False}
            with sqlite3.connect(state/'wallet.sqlite') as db:
                assert db.execute('SELECT sats FROM funds').fetchone()[0]==9900
                assert db.execute('SELECT count(*) FROM spends').fetchone()[0]==1
            with sqlite3.connect(state/'local-ledger.sqlite') as db:
                events=[x[0] for x in db.execute('SELECT event FROM events')]
                assert 'RESPONSE_PROVED' in events and 'FAILURE_RESPONSE_PROVED' in events
            report['languages'][language]={'allowedResponse':'verified','deniedResponse':'verified','wrongRequestDigest':'rejected','signedEvents':'present','walletEffects':1}
        finally:
            if proc.poll() is None:proc.send_signal(signal.SIGTERM)
            try:proc.communicate(timeout=20)
            except subprocess.TimeoutExpired:proc.kill();proc.communicate();raise
            if proc.returncode:raise RuntimeError(f'{language} agent exited {proc.returncode}')
    (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
