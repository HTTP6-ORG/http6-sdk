#!/bin/sh
# Build only the public Go host and assemble the precompiled WASIX demo guests.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -ne 1 ]; then echo 'usage: assemble-demo.sh NEW_OUTPUT_DIRECTORY' >&2; exit 2; fi
out=$1
if [ -e "$out" ]; then echo 'output directory already exists' >&2; exit 1; fi
mkdir -m 700 "$out"
out=$(CDPATH= cd -- "$out" && pwd)
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$root/circuits/demo-wasix-02/bin" && sha256sum -c ../SHA256SUMS)
else
  (cd "$root/circuits/demo-wasix-02/bin" && shasum -a 256 -c ../SHA256SUMS)
fi
cp "$root"/circuits/demo-wasix-02/bin/*.wasm "$out/"
(cd "$root/pilot" && CGO_ENABLED=1 go build -trimpath -o "$out/http6-pilot" ./cmd/pilot)
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$out" && sha256sum http6-pilot mint.wasm verifier.wasm child.wasm control.wasm work.wasm > SHA256SUMS)
else
  (cd "$out" && shasum -a 256 http6-pilot mint.wasm verifier.wasm child.wasm control.wasm work.wasm > SHA256SUMS)
fi
printf '%s\n' "Assembled demonstration bundle: $out" 'Review circuits/demo-wasix-02/NOTICE.md and VALIDATION.json.'
