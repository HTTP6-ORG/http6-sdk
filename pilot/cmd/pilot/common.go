package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	"strings"
	"sync"
	"time"
)

type M = map[string]any

const profile = "http6-wasix-delegation-02"
const api = "/http6/v0/"

var raw64 = base64.RawURLEncoding

func obj(x any) M               { v, _ := x.(map[string]any); return v }
func st(m M, key string) string { x, _ := m[key].(string); return x }
func integer(m M, key string) int64 {
	switch x := m[key].(type) {
	case json.Number:
		i, _ := x.Int64()
		return i
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return -1
}
func canon(x any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(x); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{10})
}
func parse(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		return nil, e
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}
func copyMap(m M) M       { v, _ := parse(canon(m)); return obj(v) }
func sha(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func hash(label string, x any) string {
	return sha(append([]byte(profile+"/"+label+"\x00"), canon(x)...))
}
func nonce() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func containsNUL(s string) bool          { return strings.ContainsRune(s, 0) }
func stamp() int64                       { return time.Now().Unix() }
func public(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
func generate() ed25519.PrivateKey {
	_, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		panic(e)
	}
	return k
}
func signed(k ed25519.PrivateKey, m M) string {
	h := M{"alg": "Ed25519", "kid": public(k), "typ": "http6-wasix-delegation+jws"}
	input := raw64.EncodeToString(canon(h)) + "." + raw64.EncodeToString(canon(m))
	return input + "." + raw64.EncodeToString(ed25519.Sign(k, []byte(input)))
}
func readSigned(token, key, kind string) (M, error) {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil, errors.New("compact signature shape")
	}
	pk, e := hex.DecodeString(key)
	if e != nil || len(pk) != 32 {
		return nil, errors.New("public key")
	}
	header := M{"alg": "Ed25519", "kid": key, "typ": "http6-wasix-delegation+jws"}
	sig, e := raw64.DecodeString(p[2])
	if p[0] != raw64.EncodeToString(canon(header)) || e != nil || !ed25519.Verify(pk, []byte(p[0]+"."+p[1]), sig) {
		return nil, errors.New("signature failed")
	}
	b, e := raw64.DecodeString(p[1])
	if e != nil {
		return nil, e
	}
	v, e := parse(b)
	m := obj(v)
	if e != nil || !bytes.Equal(b, canon(m)) || st(m, "v") != profile || st(m, "kind") != kind {
		return nil, errors.New("signed statement type")
	}
	return m, nil
}
func claims(kind string, fields M) M { fields["v"] = profile; fields["kind"] = kind; return fields }
func assert(ok bool, reason string) error {
	if !ok {
		return errors.New(reason)
	}
	return nil
}

type guest struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	mu  sync.Mutex
}

func newGuest(bin, name string) (*guest, error) {
	p := exec.Command("wasmer", "run", "--no-tty", "--disable-cache", filepath.Join(bin, name+".wasm"))
	p.Stderr = os.Stderr
	in, e := p.StdinPipe()
	if e != nil {
		return nil, e
	}
	out, e := p.StdoutPipe()
	if e != nil {
		return nil, e
	}
	if e = p.Start(); e != nil {
		return nil, e
	}
	return &guest{cmd: p, in: in, out: bufio.NewReader(out)}, nil
}
func (g *guest) call(cmd string, m M) (value any, err error) {
	if os.Getenv("HTTP6_PILOT_REPORT_DIR") != "" {
		switch cmd {
		case "prepare", "policy", "family", "wallet-refusal", "historical-refusal", "historical-wire", "verify", "wire", "control", "challenge", "sign-wallet-proposal", "refuse-wallet", "present", "request", "root":
			start := time.Now()
			defer func() {
				row := M{"kind": "guest", "command": cmd, "input": m, "output": value}
				if err != nil {
					row["error"] = err.Error()
				}
				if captureErr := reportTrace(start, row); captureErr != nil && err == nil {
					err = captureErr
				}
			}()
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	q := M{"cmd": cmd}
	for k, v := range m {
		q[k] = v
	}
	if _, e := g.in.Write(append(canon(q), 10)); e != nil {
		return nil, e
	}
	line, e := g.out.ReadBytes(10)
	if e != nil {
		return nil, fmt.Errorf("compiled %s: %w", cmd, e)
	}
	v, e := parse(line)
	if e != nil {
		return nil, e
	}
	r := obj(v)
	if r["ok"] != true {
		return nil, errors.New(st(r, "error"))
	}
	return r["value"], nil
}
func (g *guest) close() {
	g.in.Close()
	if g.cmd != nil {
		g.cmd.Wait()
	}
}
func manifest(bin string) (M, error) {
	data, e := os.ReadFile(filepath.Join(bin, "SHA256SUMS"))
	if e != nil {
		return nil, e
	}
	allowed := map[string]bool{"http6-pilot": true, "mint.wasm": true, "verifier.wasm": true, "child.wasm": true, "control.wasm": true, "work.wasm": true}
	m := M{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		p := strings.Fields(line)
		if len(p) != 2 || !allowed[p[1]] || m[p[1]] != nil {
			return nil, errors.New("invalid binary manifest")
		}
		b, e := os.ReadFile(filepath.Join(bin, p[1]))
		if e != nil || sha(b) != p[0] {
			return nil, errors.New("binary digest mismatch")
		}
		if strings.HasSuffix(p[1], ".wasm") && !bytes.HasPrefix(b, []byte{0, 97, 115, 109, 1, 0, 0, 0}) {
			return nil, errors.New("compiled WebAssembly required")
		}
		m[p[1]] = p[0]
	}
	if len(m) != len(allowed) {
		return nil, errors.New("incomplete binary bundle")
	}
	return m, nil
}
func artifact(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, 10), 0644)
}

type apiError struct {
	Status int
	Code   string
}

func (e *apiError) Error() string { return e.Code }
func deny(code string) error      { return &apiError{403, code} }
func postClient(ca string, sockets map[string]string) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca))
	tr := &http.Transport{DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool}, Proxy: nil}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		if p := sockets[addr]; p != "" {
			return d.DialContext(ctx, "unix", p)
		}
		if strings.HasSuffix(strings.Split(addr, ":")[0], ".local") {
			return nil, errors.New("private socket unavailable")
		}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func exchange(c *http.Client, method, url string, body any, h M) (value any, err error) {
	var status int
	if os.Getenv("HTTP6_PILOT_REPORT_DIR") != "" {
		start := time.Now()
		defer func() {
			row := M{"kind": "http", "method": method, "url": url, "headers": h, "body": body, "status": status, "response": value}
			if err != nil {
				row["error"] = err.Error()
			}
			if captureErr := reportTrace(start, row); captureErr != nil && err == nil {
				err = captureErr
			}
		}()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(canon(body))
	}
	req, e := http.NewRequest(method, url, reader)
	if e != nil {
		return nil, e
	}
	for k, v := range h {
		sv, ok := v.(string)
		if !ok {
			return nil, errors.New("non-string header")
		}
		req.Header.Set(k, sv)
	}
	if body != nil && req.Header.Get("content-type") == "" {
		req.Header.Set("content-type", "application/json")
	}
	resp, e := c.Do(req)
	if e != nil {
		return nil, e
	}
	status = resp.StatusCode
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > 2<<20 {
		return nil, errors.New("response body limit")
	}
	val, e := parse(b)
	if e != nil || !bytes.Equal(b, canon(val)) {
		return nil, errors.New("noncanonical response")
	}
	if resp.StatusCode >= 300 {
		return val, &apiError{resp.StatusCode, st(obj(val), "error")}
	}
	contentType := resp.Header.Values("Content-Type")
	if resp.StatusCode != 200 || len(contentType) != 1 || contentType[0] != "application/json" || resp.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("response HTTP metadata mismatch")
	}
	return val, nil
}
func requestBody(r *http.Request) (M, error) {
	b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || len(b) > 65536 {
		return nil, deny("BODY_LIMIT")
	}
	v, e := parse(b)
	if e != nil || obj(v) == nil || !bytes.Equal(b, canon(v)) {
		return nil, deny("NONCANONICAL_BODY")
	}
	return obj(v), nil
}
func answer(w http.ResponseWriter, v any, e error) {
	status := 200
	if e != nil {
		status = 403
		var a *apiError
		if errors.As(e, &a) {
			status = a.Status
		}
		d := obj(v)
		if d == nil {
			d = M{}
		}
		d["error"] = e.Error()
		v = d
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	w.Write(canon(v))
}

var wireKeys = []string{"content-type", "content-digest", "http6-proof", "http6-policy", "http6-certificate", "signature-input", "signature"}

func readWire(r *http.Request) (M, error) {
	b, e := requestBody(r)
	if e != nil {
		return nil, e
	}
	h := M{}
	for _, k := range wireKeys {
		vs := r.Header.Values(k)
		if len(vs) != 1 {
			return nil, deny("MISSING_OR_DUPLICATE_SIGNATURE_FIELD")
		}
		h[k] = vs[0]
	}
	return M{"body": b, "headers": h}, nil
}
func publicProof(w M) (M, error) {
	field := st(obj(w["headers"]), "http6-proof")
	if len(field) < 3 || field[0] != ':' || field[len(field)-1] != ':' {
		return nil, deny("PROOF_FRAMING")
	}
	b, e := base64.StdEncoding.DecodeString(field[1 : len(field)-1])
	if e != nil {
		return nil, e
	}
	x, e := parse(b)
	return obj(x), e
}
