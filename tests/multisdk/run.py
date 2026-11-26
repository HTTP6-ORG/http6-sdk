#!/usr/bin/env python3
"""Exercise the four SDKs against fresh private synthetic pilot instances."""
import argparse, json, os, pathlib, shutil, signal, sqlite3, subprocess, sys, time
ROOT=pathlib.Path(__file__).resolve().parents[2]
def run(args, **kw): return subprocess.run([str(x) for x in args],check=True,capture_output=True,text=True,timeout=180,**kw).stdout.strip()
def main():
 p=argparse.ArgumentParser();p.add_argument('--pilot',required=True,type=pathlib.Path);p.add_argument('--out',required=True,type=pathlib.Path);p.add_argument('--dotnet',default='dotnet');a=p.parse_args()
 binary=a.pilot.resolve(strict=True);out=a.out.resolve();out.mkdir(mode=0o700,parents=False,exist_ok=False);build=out/'build';build.mkdir(mode=0o700)
 env=os.environ.copy();env.update({'CARGO_TARGET_DIR':str(build/'rust-target'),'GOCACHE':str(build/'go-cache'),'DOTNET_CLI_HOME':str(build/'dotnet-home'),'DOTNET_NOLOGO':'1','DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1','DOTNET_CLI_TELEMETRY_OPTOUT':'1'})
 go=build/'go-e2e';run(['go','build','-o',go,'./cmd/e2e'],cwd=ROOT/'packages/go',env=env)
 run(['cargo','build','--locked','--offline','--example','e2e'],cwd=ROOT/'packages/rust',env=env)
 # Copy only the SDK and test source into scratch so dotnet's generated files remain private to this run.
 cp=build/'csharp';(cp/'packages').mkdir(parents=True);(cp/'tests/multisdk').mkdir(parents=True)
 shutil.copytree(ROOT/'packages/csharp',cp/'packages/csharp',ignore=shutil.ignore_patterns('obj','bin'))
 shutil.copytree(ROOT/'tests/multisdk/csharp',cp/'tests/multisdk/csharp',ignore=shutil.ignore_patterns('obj','bin'))
 run([a.dotnet,'build',cp/'tests/multisdk/csharp/E2E.csproj','-c','Release','-o',build/'csharp-bin','--nologo'],env=env)
 commands={'python':[sys.executable,ROOT/'packages/python/tests/e2e.py'],'go':[go],'rust':[build/'rust-target/debug/examples/e2e'],'csharp':[a.dotnet,build/'csharp-bin/E2E.dll']}
 results={}
 for name,command in commands.items():
  state=out/name;proc=subprocess.Popen([str(binary),'agent','--state',str(state)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   for _ in range(300):
    if (state/'connections.json').exists():break
    if proc.poll() is not None:raise RuntimeError('pilot exited: '+proc.stderr.read())
    time.sleep(.1)
   else:raise RuntimeError('pilot startup timed out')
   config=json.loads((state/'connections.json').read_text());assert config['profile']=='http6-wasix-delegation-02'
   result=json.loads(run([*command,state,binary,config['operatorKey'],config['localLedgerKey']],env=env));assert result['language']==name
   with sqlite3.connect(state/'wallet.sqlite') as db:
    assert db.execute('select sats from funds').fetchone()[0]==9900
    assert db.execute('select count(*) from spends').fetchone()[0]==1
   results[name]=result
  finally:
   if proc.poll() is None:proc.send_signal(signal.SIGTERM)
   try:proc.communicate(timeout=20)
   except subprocess.TimeoutExpired:proc.kill();proc.communicate();raise
   if proc.returncode:raise RuntimeError(f'{name} agent exited {proc.returncode}')
 report={'profile':'http6-wasix-delegation-02','scope':'synthetic single-host pilot; fixture pins are local; no latest-head or external effect claim','sdks':results}
 (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
