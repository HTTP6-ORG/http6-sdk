# Compiled WASIX 02 demonstration

This folder contains compiled WebAssembly guests for the synthetic HTTP6 WASIX 02 pilot. ENI6MA circuit source, guest source, vendor crates and private provisions are not included. The `work.wasm` file is an ordinary sample worker, not an ENI6MA circuit. These artifacts support the synthetic demonstration.

The exact artifact hashes and local test results are in [VALIDATION.json](VALIDATION.json). The same bytes passed the pilot's 98-check audit on macOS ARM64 and on emulated Linux AMD64. The AMD64 check was not on native AMD64 hardware. Those tests used synthetic data, a single operator, and Wasmer 7.4.0. The test environments and results are listed above.

Check [SHA256SUMS](SHA256SUMS) from the `bin` directory. An application also needs the matching profile 02 Go host and a compatible Wasmer runtime. The repository's `pilot/assemble-demo.sh` builds the host from the published host integration source, copies these compiled guests to a new directory, and writes the manifest expected by the pilot. Its output contains synthetic demonstration software only.

Copyright © 2026 ENI6MA and Rosario Cybernetics. Patent pending. Read the adjacent [NOTICE.md](NOTICE.md) before using these artifacts. Nonprofit organizations and private entities may contact Rosario Cybernetics to request permission. Commercial use requires a paid commercial license. Third-party dependency notices are in [THIRD_PARTY](THIRD_PARTY/); they do not grant rights to the ENI6MA circuit.
