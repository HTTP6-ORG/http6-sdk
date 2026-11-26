// Package http6 is an experimental local WASIX 02 pilot adapter.
package http6

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"time"
)

const Profile = "http6-wasix-delegation-02"

var keyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var metadata = map[string]bool{"failureCore": true, "failure": true, "failureDecision": true, "failureEventRef": true, "failureEvidenceFile": true, "proofStatus": true}

type Response struct {
	Status       int
	Body         map[string]any
	RequestBytes []byte
}
type Client struct{ AgentSocket, LedgerSocket, PilotBinary string }

func Attach(stateDir, pilotBinary string) (*Client, error) {
	b, e := os.ReadFile(filepath.Join(stateDir, "connections.json"))
	if e != nil {
		return nil, e
	}
	var x struct {
		Agent   string `json:"agent"`
		Ledger  string `json:"ledger"`
		Profile string `json:"profile"`
	}
	if e = json.Unmarshal(b, &x); e != nil {
		return nil, e
	}
	if x.Profile != Profile || x.Agent == "" || x.Ledger == "" {
		return nil, errors.New("profile or connections mismatch")
	}
	return &Client{x.Agent, x.Ledger, pilotBinary}, nil
}
func parse(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		return nil, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}
func (c *Client) request(sock, method, path string, body []byte) (int, any, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, e := http.NewRequest(method, "http://agent.local"+path, bytes.NewReader(body))
	if e != nil {
		return 0, nil, e
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	r, e := client.Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024+1))
	if e != nil {
		return 0, nil, e
	}
	if len(b) > 10*1024*1024 {
		return 0, nil, errors.New("response limit")
	}
	v, e := parse(b)
	return r.StatusCode, v, e
}
func (c *Client) Invoke(proposal map[string]any) (Response, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if e := encoder.Encode(proposal); e != nil {
		return Response{}, e
	}
	return c.InvokeRaw(bytes.TrimSuffix(buf.Bytes(), []byte{10}))
}
func (c *Client) InvokeRaw(b []byte) (Response, error) {
	if len(b) > 65536 {
		return Response{}, errors.New("request limit")
	}
	status, v, e := c.request(c.AgentSocket, "POST", "/http6/v0/propose", b)
	if e != nil {
		return Response{}, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return Response{}, errors.New("invalid response")
	}
	return Response{status, m, append([]byte(nil), b...)}, nil
}
func (c *Client) Events() ([]any, error) {
	status, v, e := c.request(c.LedgerSocket, "GET", "/http6/v0/events", nil)
	if e != nil {
		return nil, e
	}
	rows, ok := v.([]any)
	if status != 200 || !ok {
		return nil, errors.New("ledger unavailable")
	}
	return rows, nil
}
func pins(keys ...string) error {
	for _, s := range keys {
		if !keyPattern.MatchString(s) {
			return errors.New("valid independently configured trust pins required")
		}
	}
	return nil
}
func evidence(path string) (map[string]any, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) > 10*1024*1024 {
		return nil, errors.New("evidence limit")
	}
	v, e := parse(b)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("invalid evidence")
	}
	return m, nil
}
func (c *Client) verify(command string, args []string, value any) ([]byte, error) {
	d, e := os.MkdirTemp("", "http6-sdk-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(d)
	file := filepath.Join(d, "evidence.json")
	b, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	if e = os.WriteFile(file, b, 0600); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	all := append([]string{command}, args...)
	all = append(all, file)
	out, e := exec.CommandContext(ctx, c.PilotBinary, all...).Output()
	if e != nil {
		return nil, errors.New("native verifier rejected evidence")
	}
	return out, nil
}
func compare(b, e map[string]any, keys ...string) error {
	for _, k := range keys {
		x, ok := b[k]
		if !ok || !reflect.DeepEqual(x, e[k]) {
			return fmt.Errorf("evidence mismatch: %s", k)
		}
	}
	return nil
}
func (c *Client) VerifyResponse(r Response, evidenceFile, operatorKey, ledgerKey, expectedOp string) error {
	if e := pins(operatorKey, ledgerKey); e != nil {
		return e
	}
	response, ok := r.Body["response"].(map[string]any)
	if !ok {
		return errors.New("response missing")
	}
	ctx, ok := response["context"].(map[string]any)
	if !ok || ctx["op"] != expectedOp || r.Status != 200 {
		return errors.New("response status or operation mismatch")
	}
	ev, e := evidence(evidenceFile)
	if e != nil {
		return e
	}
	if e = compare(r.Body, ev, "result", "receipt", "response", "responseDecision", "responseEventRef"); e != nil {
		return e
	}
	_, e = c.verify("verify-response", []string{"--operator-key", operatorKey, "--ledger-key", ledgerKey}, ev)
	return e
}
func (c *Client) VerifyFailure(r Response, evidenceFile, operatorKey, ledgerKey string) error {
	if e := pins(operatorKey, ledgerKey); e != nil {
		return e
	}
	core := map[string]any{}
	for k, v := range r.Body {
		if !metadata[k] {
			core[k] = v
		}
	}
	if r.Body["proofStatus"] != "ledger-recorded" || !reflect.DeepEqual(core, r.Body["failureCore"]) {
		return errors.New("failure response mismatch")
	}
	ev, e := evidence(evidenceFile)
	if e != nil {
		return e
	}
	if e = compare(r.Body, ev, "failureCore", "failure", "failureDecision", "failureEventRef", "error"); e != nil {
		return e
	}
	sum := sha256.Sum256(r.RequestBytes)
	digest := hex.EncodeToString(sum[:])
	if ev["requestHash"] != digest || fmt.Sprint(ev["status"]) != strconv.Itoa(r.Status) {
		return errors.New("request or status mismatch")
	}
	_, e = c.verify("verify-failure", []string{"--operator-key", operatorKey, "--ledger-key", ledgerKey, "--request-hash", digest, "--status", strconv.Itoa(r.Status)}, ev)
	return e
}
func (c *Client) VerifyLedger(rows []any, ledgerKey string) (map[string]any, error) {
	if e := pins(ledgerKey); e != nil {
		return nil, e
	}
	out, e := c.verify("verify-ledger", []string{"--ledger-key", ledgerKey}, rows)
	if e != nil {
		return nil, e
	}
	v, e := parse(out)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("invalid verification result")
	}
	return m, nil
}
