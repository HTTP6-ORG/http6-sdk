package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var audiences = []string{"endpoint", "process", "database", "wallet"}
var roles = []string{"ledger", "local-ledger", "broker", "endpoint", "process", "database", "wallet"}

func unixRole(role string) bool { return role != "ledger" && role != "endpoint" }

type authority struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pem  string
}

func newCA() (*authority, error) {
	k := generate()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "HTTP6 local test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	b, e := x509.CreateCertificate(rand.Reader, cert, cert, k.Public(), k)
	if e != nil {
		return nil, e
	}
	return &authority{cert, k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))}, nil
}
func (a *authority) issue(role string) (string, string, error) {
	k := generate()
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return "", "", e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: role}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	b, e := x509.CreateCertificate(rand.Reader, cert, a.cert, k.Public(), a.key)
	if e != nil {
		return "", "", e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return "", "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})), nil
}

type service struct {
	role, base, socket, key, responseCircuit, responseVerifier string
	pid                                                        int
	cmd                                                        *exec.Cmd
	in                                                         io.WriteCloser
	out                                                        *bufio.Reader
}

func line(r *bufio.Reader) (M, error) {
	b, e := r.ReadBytes(10)
	if e != nil {
		return nil, e
	}
	v, e := parse(b)
	return obj(v), e
}
func launch(bin, tmp, role string) (*service, error) {
	s := &service{role: role}
	var ln net.Listener
	var file *os.File
	var e error
	if unixRole(role) {
		s.socket = filepath.Join(tmp, role+".sock")
		var l *net.UnixListener
		l, e = net.ListenUnix("unix", &net.UnixAddr{Name: s.socket, Net: "unix"})
		if e != nil {
			return nil, e
		}
		ln = l
		l.SetUnlinkOnClose(false)
		defer ln.Close()
		if e = os.Chmod(s.socket, 0600); e != nil {
			return nil, e
		}
		s.base = "http://" + role + ".local"
		file, e = l.File()
	} else {
		var l *net.TCPListener
		l, e = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			return nil, e
		}
		ln = l
		defer ln.Close()
		s.base = "https://" + ln.Addr().String()
		file, e = l.File()
	}
	if e != nil {
		return nil, e
	}
	defer file.Close()
	s.cmd = exec.Command(filepath.Join(bin, "http6-pilot"), "__serve", role, bin)
	s.cmd.Stderr = os.Stderr
	s.cmd.ExtraFiles = []*os.File{file}
	s.in, e = s.cmd.StdinPipe()
	if e != nil {
		return nil, e
	}
	out, e := s.cmd.StdoutPipe()
	if e != nil {
		return nil, e
	}
	s.out = bufio.NewReader(out)
	if e = s.cmd.Start(); e != nil {
		return nil, e
	}
	hello, e := line(s.out)
	if e != nil {
		s.close()
		return nil, fmt.Errorf("%s bootstrap: %w", role, e)
	}
	s.key = st(hello, "key")
	s.responseCircuit = st(hello, "responseCircuit")
	s.responseVerifier = st(hello, "responseVerifier")
	s.pid = s.cmd.Process.Pid
	return s, nil
}
func (s *service) configure(cfg M) error {
	if _, e := s.in.Write(append(canon(cfg), 10)); e != nil {
		return e
	}
	v, e := line(s.out)
	if e != nil {
		return e
	}
	return assert(v["ready"] == true, "service not ready")
}
func (s *service) availability(ready bool) error {
	return s.setFault(M{"cmd": "availability", "ready": ready})
}
func (s *service) setFault(m M) error {
	if _, e := s.in.Write(append(canon(m), 10)); e != nil {
		return e
	}
	m, e := line(s.out)
	if e != nil {
		return e
	}
	return assert(m["updated"] == true, "availability switch")
}
func (s *service) proveAgentFailure(requestHash string, core M, category string, status int64) (M, error) {
	if _, e := s.in.Write(append(canon(M{"cmd": "prove-agent-failure", "requestHash": requestHash, "core": core, "category": category, "status": status}), 10)); e != nil {
		return nil, e
	}
	v, e := line(s.out)
	if e != nil {
		return nil, e
	}
	if v["ok"] != true {
		return nil, errors.New("failure proof unavailable")
	}
	return obj(v["value"]), nil
}
func (s *service) testFailureReplay(failure M) (string, error) {
	if _, e := s.in.Write(append(canon(M{"cmd": "test-failure-replay", "failure": failure}), 10)); e != nil {
		return "", e
	}
	value, e := line(s.out)
	if e != nil {
		return "", e
	}
	return st(value, "error"), nil
}
func (s *service) testResponseReplay(wire, response M) (string, error) {
	if _, e := s.in.Write(append(canon(M{"cmd": "test-response-replay", "wire": wire, "response": response}), 10)); e != nil {
		return "", e
	}
	value, e := line(s.out)
	if e != nil {
		return "", e
	}
	return st(value, "error"), nil
}
func (s *service) close() {
	if s.in == nil {
		return
	}
	s.in.Close()
	s.in = nil
	s.cmd.Wait()
}
func runServer(role, bin string) error {
	if _, e := manifest(bin); e != nil {
		return e
	}
	verifier, e := newGuest(bin, "verifier")
	if e != nil {
		return e
	}
	defer verifier.close()
	var ctrl *guest
	var key, responseCircuit, responseVerifier string
	vh, e := verifier.call("hello", nil)
	if e != nil {
		return e
	}
	responseVerifier = st(obj(vh), "key")
	var signer ed25519.PrivateKey
	if role == "ledger" || role == "local-ledger" {
		signer = generate()
		key = public(signer)
	} else {
		ctrl, e = newGuest(bin, "control")
		if e != nil {
			return e
		}
		defer ctrl.close()
		v, e := ctrl.call("hello", nil)
		if e != nil {
			return e
		}
		key = st(obj(v), "key")
		responseCircuit = st(obj(v), "responseCircuit")
	}
	emit := func(m M) { os.Stdout.Write(append(canon(m), 10)) }
	emit(M{"key": key, "responseCircuit": responseCircuit, "responseVerifier": responseVerifier})
	buf := bufio.NewReader(os.Stdin)
	cfg, e := line(buf)
	if e != nil {
		return e
	}
	t := obj(cfg["trust"])
	if _, e = verifier.call("configure", M{"trust": t}); e != nil {
		return e
	}
	db, e := openDB(filepath.Join(st(cfg, "out"), role+".sqlite"))
	if e != nil {
		return e
	}
	defer db.close()
	var handler http.Handler
	var f *front
	if role == "ledger" || role == "local-ledger" {
		l := &ledger{base: st(cfg, "base"), db: db, verifier: verifier, trust: t, signer: signer}
		if e = l.init(); e != nil {
			return e
		}
		handler = l
		stop := make(chan struct{})
		done := make(chan struct{})
		go l.sweep(stop, done)
		defer func() { close(stop); <-done }()
	} else {
		c := obj(obj(t["controls"])[role])
		if _, e = ctrl.call("configure", M{"trust": t, "operator": t["operator"], "ledger": t["ledger"], "policy": c["policy"], "cert": c["cert"]}); e != nil {
			return e
		}
		{
			seed, err := ctrl.call("provision-response", nil)
			if err != nil {
				return err
			}
			if _, err = verifier.call("enroll-response", M{"role": role, "privateProvision": seed}); err != nil {
				return err
			}
		}
		sockets := map[string]string{}
		for host, v := range obj(cfg["sockets"]) {
			sockets[host] = v.(string)
		}
		f = &front{role: role, bin: bin, verifier: verifier, control: ctrl, trust: t, client: postClient(st(cfg, "ca"), sockets), db: db}
		if e = f.init(); e != nil {
			return e
		}
		handler = f
	}
	inherited := os.NewFile(3, "listener")
	ln, e := net.FileListener(inherited)
	inherited.Close()
	if e != nil {
		return e
	}
	defer ln.Close()
	if !unixRole(role) {
		cert, e := tls.X509KeyPair([]byte(st(cfg, "certificate")), []byte(st(cfg, "tlsKey")))
		if e != nil {
			return e
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 6 * time.Second, WriteTimeout: 8 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 32768,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, ingressContextKey{}, &ingressSession{})
		}}
	go func() {
		for {
			m, err := line(buf)
			if err != nil {
				break
			}
			if f != nil && f.role == "broker" && m["cmd"] == "prove-agent-failure" {
				v, err := f.proveFailure(st(m, "requestHash"), obj(m["core"]), st(m, "category"), integer(m, "status"))
				if err != nil {
					emit(M{"ok": false, "error": err.Error()})
				} else {
					emit(M{"ok": true, "value": v})
				}
				continue
			}
			if f != nil && f.role == "broker" && m["cmd"] == "test-failure-replay" && os.Getenv("HTTP6_PILOT_RESPONSE_TEST") == "1" {
				_, err := f.failureCall("failure-commit", M{"nonce": nonce(), "failure": m["failure"]})
				result := "unexpected acceptance"
				if err != nil {
					result = err.Error()
				}
				emit(M{"error": result})
				continue
			}
			if f != nil && m["cmd"] == "test-response-replay" && os.Getenv("HTTP6_PILOT_RESPONSE_TEST") == "1" {
				wire := obj(m["wire"])
				info, _, err := f.verify(wire)
				if err == nil {
					_, err = f.callback("response-commit", "allowed", wire, info, M{"response": m["response"]})
				}
				result := "unexpected acceptance"
				if err != nil {
					result = err.Error()
				}
				emit(M{"error": result})
				continue
			}
			if f != nil && m["cmd"] == "test-fail-after-redeem" && os.Getenv("HTTP6_PILOT_RESPONSE_TEST") == "1" {
				f.delayAfterRedeem.Store(integer(m, "delayMillis"))
				f.failAfterRedeem.Store(true)
				emit(M{"updated": true})
				continue
			}
			if f != nil && m["cmd"] == "latency" {
				f.lagMillis.Store(integer(m, "ms"))
				emit(M{"updated": true})
			}
			if f != nil && m["cmd"] == "availability" {
				f.paused.Store(m["ready"] != true)
				emit(M{"updated": true})
			}
		}
		srv.Close()
	}()
	emit(M{"ready": true})
	if e = srv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
		return e
	}
	return nil
}
