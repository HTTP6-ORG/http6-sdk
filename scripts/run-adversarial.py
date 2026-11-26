#!/usr/bin/env python3
"""Run synthetic adversarial comparisons and retain logs in a new private directory."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'TestAdversarialBearerCredentialCopy', 'TestAdversarialSignedStatementManipulation',
    'TestAdversarialCopiedLedgerSigningKey', 'TestAdversarialFakeTLSEndpoint',
    'TestAdversarialTrustedTLSProxyCanCaptureBearerJWT',
    'TestAdversarialProxyRejectsKeyAndSourceRequests',
    'TestAdversarialReadableEnvCredentialCanAuthorizeLocalService',
    'TestAdversarialSyntheticKeyStorage',
    'TestAdversarialStolenLivePresentation', 'TestAdversarialPromptLikeKeyRequests', 'TestFailureProofEndToEnd',
    'TestVerifyLedgerRows', 'TestResponseHTTPMetadataAndCanonicalBytes',
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pilot-bin', type=Path, required=True, help='assembled compiled demonstration bundle')
    parser.add_argument('--out', type=Path, required=True, help='new directory for private logs')
    parser.add_argument('--iterations', type=int, default=3, choices=range(1, 26))
    args = parser.parse_args()
    binary = args.pilot_bin.resolve(strict=True)
    out = args.out.resolve()
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    command = ['go', 'test', '-json', './cmd/pilot', '-run',
               '^(TestAdversarial|TestFailureProofEndToEnd|TestVerifyLedgerRows|TestResponseHTTPMetadataAndCanonicalBytes)',
               '-count', str(args.iterations), '-v', '-args', '-trace-release', str(binary)]
    print('Running synthetic attacks. Logs remain in:', out, flush=True)
    with (out / 'go-test.jsonl').open('w', encoding='utf-8') as stdout, (out / 'stderr.log').open('w', encoding='utf-8') as stderr:
        result = subprocess.run(command, cwd=ROOT / 'pilot', stdout=stdout, stderr=stderr, env=os.environ.copy())
    counts = {name: {'passed': 0, 'failed': 0, 'skipped': 0} for name in EXPECTED}
    for line in (out / 'go-test.jsonl').read_text(encoding='utf-8').splitlines():
        event = json.loads(line)
        name, action = event.get('Test'), event.get('Action')
        if name in counts and action in ('pass', 'fail', 'skip'):
            counts[name][{'pass': 'passed', 'fail': 'failed', 'skip': 'skipped'}[action]] += 1
    passed = result.returncode == 0 and all(value == {'passed': args.iterations, 'failed': 0, 'skipped': 0} for value in counts.values())
    summary = {
        'profile': 'http6-wasix-delegation-02',
        'timestampUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'iterations': args.iterations, 'tests': counts, 'allChecksCompleted': passed,
        'observations': [
            'A trusted interception root can observe a synthetic bearer JWT; an unrelated untrusted TLS authority is rejected.',
            'A copied bearer JWT is accepted by the deliberately bearer-only comparison service, while a copied HTTP6 presentation without the live holder is rejected.',
            'The gateway rejects raw text, prompt-like fields, source or binary resource requests and string key requests; a valid typed sum returns only its result payload.',
            'A compromised synthetic ledger signing key can sign a fabricated ledger history.',
            'A party allowed to read a synthetic environment variable or file can copy its key and forge a signature.',
            'A reader of a synthetic .env bearer secret can reuse it against the local HTTPS control service.',
            'The structured pilot gateway rejects injected prompt fields. No language model is tested.',
        ],
        'scope': 'Synthetic single-host test. Key extraction, real interception, separate operators and production systems are not tested.',
        'note': 'Observations apply only when all checks completed successfully. A PASS on the key-copy test confirms the limitation.',
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1

if __name__ == '__main__':
    sys.exit(main())
