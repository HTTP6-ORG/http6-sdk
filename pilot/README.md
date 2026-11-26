# WASIX response-proof pilot

This directory contains the host and guest integration for `http6-wasix-delegation-02`. It adds ledger-recorded broker observations for failure responses to the native committed-success response proof. The profile is separate from with the earlier `http6-wasix-delegation-00` or `http6-wasix-delegation-01` pilots and does not replace its archived binaries or evidence. All accounts, origins and business data in its demonstrations are synthetic.

The ENI6MA circuit, WASIX guest source and vendor crates are not distributed in the public repository. The repository provides [compiled demonstration guests](../circuits/demo-wasix-02/) with checksums, a rights notice and narrowly scoped synthetic test results. Review their license before use. For production or other implementations, obtain an authorized, validated profile-compatible bundle separately from ENI6MA or Rosario Cybernetics. The Go host integration source is included for review; it requires the matching approved guest artifacts and a matching checksum manifest. Circuit and private provision material must not be committed.

To assemble a local demonstration host and guest bundle, provide a new private output directory. The Go compiler, cgo, SQLite headers, and Wasmer 7.4.0 are required:

```sh
./pilot/assemble-demo.sh /private/path/to/a-new-demo-bin
/private/path/to/a-new-demo-bin/http6-pilot demo --out /private/path/to/a-new-private-evidence-directory
```

The demo exercises endpoint, process, database and wallet operations, checks tampering and response replay, and audits signed ledger events and resource journals. An unavailable response proof after an effect can leave delivery uncertain.

The resource creates a separately provisioned response circuit and hands its private reference to a separate local verifier over a private startup pipe. The ledger issues an unpredictable, one-use response challenge after the resource has recorded its outcome. The response context binds the request, presentation, policy, recipient, certificate, signed receipt, status and result digest. A designated verifier checks the native response and signs a proof. The ledger validates and records its references before the broker confirms. An independent verifier can check historical response evidence using configured operator and ledger pins.

This is a designated-verifier, single-host fixture. The public transcript and verifier signature use a designated-verifier proof model. Failure proofs record the broker observation and report caller identity and effect state separately. When the ledger or verifier is unavailable, no ledger-recorded failure proof is issued. See the developer guide for the recovery, key custody, resource mediation, lookup and checkpoint behavior.
