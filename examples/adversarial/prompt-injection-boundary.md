# Prompt-like proxy requests

The pilot receives synthetic prompt text asking it to reveal a key, extra prompt fields, and guessed secret-export commands. No language model is connected.

First assemble the compiled demonstration bundle, then run from the repository root:

~~~sh
./pilot/assemble-demo.sh /private/path/to/new-demo-bin
cd pilot
go test ./cmd/pilot -run '^TestAdversarialPromptLikeKeyRequests$' -count=1 -args -trace-release /private/path/to/new-demo-bin/http6-pilot
~~~

Expected observation: extra fields and guessed commands are refused, no resource effect occurs, and the checked fixture files contain none of the requested secret labels. This demonstrates the gateway schema behavior, not resistance to every model prompt attack.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_external_test.go).
