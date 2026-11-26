# Replay and changed requests

This test compares copied EdDSA and RS256 bearer tokens with a holder-bound HTTP6 presentation. It also changes request arguments, retries a spent presentation, and checks that rejected copies cause no resource effect.

First assemble the compiled demonstration bundle, then run from the repository root:

~~~sh
./pilot/assemble-demo.sh /private/path/to/new-demo-bin
cd pilot
go test ./cmd/pilot -run '^TestAdversarialStolenLivePresentation$' -count=1 -args -trace-release /private/path/to/new-demo-bin/http6-pilot
~~~

Expected observation: copied bearer tokens can replay the deliberately bearer-only control and authorize a changed sum. The copied HTTP6 presentation without the live holder is rejected; the legitimate holder acts once; a later replay is refused.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_external_test.go).
