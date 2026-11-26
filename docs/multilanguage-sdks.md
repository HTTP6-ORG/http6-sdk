---
sidebar_position: 6
---

# Python, Rust, Go and C# pilot SDKs

These proposed, basic SDKs attach to an existing `http6-wasix-delegation-02` agent and the matching approved pilot verifier. They submit bounded requests, preserve exact bytes for failure proofs, retrieve ledger rows, compare returned proof evidence, and invoke the independently supplied pilot verifier. They do not contain the ENI6MA circuit or WASIX guest source. They are experimental local adapters, not production SDKs, cryptographic libraries, unrestricted minting APIs, or standalone circuit implementations.

| Language | Package location | Main APIs |
| --- | --- | --- |
| Python | `packages/python` | `PilotClient.attach`, `invoke`, `invoke_raw`, `events`, `verify_response`, `verify_failure`, `verify_ledger` |
| Rust | `packages/rust` | `PilotClient::attach`, `invoke`, `invoke_raw`, `events`, `verify_response`, `verify_failure`, `verify_ledger` |
| Go | `packages/go` | `Attach`, `Invoke`, `InvokeRaw`, `Events`, `VerifyResponse`, `VerifyFailure`, `VerifyLedger` |
| C# | `packages/csharp` | `PilotClient.Attach`, `InvokeAsync`, `InvokeRawAsync`, `EventsAsync`, `VerifyResponseAsync`, `VerifyFailureAsync`, `VerifyLedgerAsync` |

The agent must already be running. Choose an authorized, validated 02 pilot bundle or assemble the published compiled demonstration guests using `pilot/assemble-demo.sh` that includes the `verify-response`, `verify-failure`, and `verify-ledger` commands. An older binary without `verify-ledger` cannot perform this SDK ledger check. Provision the operator and ledger public keys independently of the response or the `connections.json` file. The local tests use fixture keys from their own freshly created state only for reproducibility.

```python
from pathlib import Path
from http6_sdk import PilotClient

client = PilotClient.attach(state_dir, pilot_binary)
request = {'op':'payment-1','audience':'wallet','resource':'merchant-payment',
           'args':{'network':'regtest','recipient':'merchant-a','satoshis':'100'},
           'holdSeconds':4}
response = client.invoke(request)
if response.status == 200:
    result = client.verify_response(response,
        Path(state_dir) / response.body['responseEvidenceFile'],
        pinned_operator_key, pinned_ledger_key, 'payment-1')
    print(result)
elif response.body.get('proofStatus') == 'ledger-recorded':
    result = client.verify_failure(response,
        Path(state_dir) / response.body['failureEvidenceFile'],
        pinned_operator_key, pinned_ledger_key)
    print(result)
rows = client.events()
print(client.verify_ledger(rows, pinned_ledger_key))
```

The Rust, Go and C# end-to-end examples are in `packages/rust/examples/e2e.rs`, `packages/go/cmd/e2e/main.go`, and `tests/multisdk/csharp/Program.cs`. The Python package can be installed from `packages/python`, the Go module can be imported from `packages/go`, the Rust package is a local Cargo dependency, and C# applications can reference `packages/csharp/Http6.ProposedSdk.csproj`. No package is represented here as a production registry release.

The success verifier checks HTTP status, the expected operation, and the result, receipt, proof, decision and event references against a private evidence snapshot before invoking the native verifier with pinned keys. The failure verifier additionally checks the returned error core, exact original request digest, actual response status and the signed ledger evidence. It proves a historical gateway observation, not caller identity, policy correctness, or whether an effect happened. Evidence files are copied into a new private temporary directory before verification.

The ledger verifier checks signatures under the pinned ledger key, contiguous sequence, row data and the hash chain in the rows returned. It reports `eventSchemaValidated:false`; apply the published event schema separately after decoding the signed entry. `latestHeadVerified` is false: an otherwise valid prefix can be stale or incomplete. A checkpoint held by an independent authority is needed to establish a trusted latest head. The check also does not prove an external resource effect.

## End-to-end tests

With a separately provided compatible pilot binary, Node.js, Python 3, Go, Rust, .NET 8, Wasmer and pre-fetched locked Rust dependencies:

```sh
cd http6-sdk
# Populate the Rust crate cache first if needed: cargo fetch --locked --manifest-path packages/rust/Cargo.toml
python3 tests/multisdk/run.py \
  --pilot /private/path/to/a-new-demo-bin/http6-pilot \
  --out /private/path/to/a-new-sdk-test-directory \
  --dotnet dotnet
```

The runner compiles all four SDK test programs, creates a new private agent state for each, and retains the output directory. Each test verifies an allowed response, a denied response, a malformed response, wrong trust pins, altered response or request bytes, and a modified ledger row. It checks one synthetic wallet effect. The tests use an experimental single-host fixture and do not establish an independent operator, current authority, production settlement or an information-theoretic guarantee. See the [qualification report](https://www.http6.org/developers/sdk/artifacts/multisdk-02-qualification.json).

The [WASIX 02 ledger schema](https://www.http6.org/developers/sdk/artifacts/wasix-ledger-02.schema.json) now defines the common row and signed-entry envelopes and event data for all 19 event types recorded by this pilot. Schema validation is syntactic. A ledger row contains JSON text in `data`; decode it and compare it to the verified signed entry before applying event semantics. The schema does not verify signatures, object availability, chain freshness, resource effects, or claims outside this pilot profile. Unknown event kinds must be rejected until a profile update defines them.

ENI6MA circuits are patent pending and protected by copyright. Commercial deployments require a license from ENI6MA or [Rosario Cybernetics](https://www.rosariocyber.com/contact). Contact President Frank Rosario there about production and extended implementations. The public repository does not distribute circuit source or private provisions.

Nonprofit organizations and private entities may contact Rosario Cybernetics directly to request permission. Commercial use is strictly prohibited without a paid commercial license. See the [circuit notice](https://github.com/HTTP6-ORG/http6-sdk/blob/main/circuits/NOTICE.md).
