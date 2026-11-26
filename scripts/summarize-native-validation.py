#!/usr/bin/env python3
"""Publish only bounded test results, never the private synthetic ledger or provisions."""
import hashlib,json,os,pathlib,platform,sys
pilot=json.loads(pathlib.Path(sys.argv[1]).read_text());sdk=json.loads(pathlib.Path(sys.argv[2]).read_text());root=pathlib.Path(__file__).resolve().parents[1]
assert pilot['existingRuntime']['checks']==98 and '0 restricted effects' in pilot['existingRuntime']['audited']
assert set(sdk['sdks'])=={'python','rust','go','csharp'}
for result in sdk['sdks'].values():
 assert all(result.get(k) is True for k in ('success','denied','malformed','tamperingRejected','ledgerVerified'))
expected=json.loads((root/'circuits/demo-wasix-02/VALIDATION.json').read_text())['artifactsSha256']
actual={n:hashlib.sha256((root/'circuits/demo-wasix-02/bin'/n).read_bytes()).hexdigest() for n in expected}
assert actual==expected
summary={'profile':'http6-wasix-delegation-02','scope':'public compiled guests, synthetic data, one GitHub-hosted VM and operator','repositoryCommit':os.environ['GITHUB_SHA'],'runId':os.environ['GITHUB_RUN_ID'],'runnerLabel':os.environ['TEST_RUNNER'],'runnerArchitecture':os.environ['RUNNER_ARCH'],'machine':platform.machine(),'expectedMachine':os.environ['TEST_MACHINE'],'compiledGuestSha256':actual,'pilotChecks':pilot['existingRuntime']['checks'],'pilotAudit':pilot['existingRuntime']['audited'],'failureAndLedgerTests':'passed','nodeSdkTests':'passed','sdks':sdk['sdks'],'limits':['GitHub-hosted architecture-labelled virtual machine','synthetic fixture and same-host trust pins','not independent operator, production settlement, or a cryptographic security proof']}
assert summary['runnerArchitecture']==os.environ['TEST_ARCH'] and summary['machine']==summary['expectedMachine']
pathlib.Path(sys.argv[3]).write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
