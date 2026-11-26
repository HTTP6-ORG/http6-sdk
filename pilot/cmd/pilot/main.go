package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A developer can launch the two protected guests before choosing a policy.
// Private sockets pass one lifetime of ownership of their existing byte streams.
func attachGuest(dir, name string) (*guest, error) {
	st, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("runtime directory must be private")
	}
	c, e := net.DialTimeout("unix", filepath.Join(dir, name+".sock"), 2*time.Second)
	if e != nil {
		return nil, e
	}
	return &guest{in: c, out: bufio.NewReader(c)}, nil
}
func runtimeServer(bin, dir string) error {
	if _, e := manifest(bin); e != nil {
		return e
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	// Only unlink sockets and a manifest that this instance created.
	defer os.Remove(dir)
	var guests []*guest
	var listeners []*net.UnixListener
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
		for _, g := range guests {
			g.close()
		}
	}()
	for _, name := range []string{"mint", "verifier"} {
		g, e := newGuest(bin, name)
		if e != nil {
			return e
		}
		guests = append(guests, g)
		if _, e = g.call("hello", nil); e != nil {
			return e
		}
		ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, name+".sock"), Net: "unix"})
		if e != nil {
			return e
		}
		listeners = append(listeners, ln)
		if e = os.Chmod(ln.Addr().String(), 0600); e != nil {
			return e
		}
	}
	sums, e := manifest(bin)
	if e != nil {
		return e
	}
	manifestPath := filepath.Join(dir, "builds.json")
	if e = artifact(manifestPath, sums); e != nil {
		return e
	}
	defer os.Remove(manifestPath)
	fmt.Printf("READY %s\n", dir)
	var wg sync.WaitGroup
	var peersMu sync.Mutex
	peers := []net.Conn{}
	done := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		select {
		case <-done:
			return
		case <-signals:
			for _, l := range listeners {
				l.Close()
			}
			peersMu.Lock()
			for _, c := range peers {
				c.Close()
			}
			peersMu.Unlock()
		}
	}()
	for idx, ln := range listeners {
		wg.Add(1)
		go func(g *guest, ln *net.UnixListener) {
			defer wg.Done()
			c, e := ln.Accept()
			ln.Close()
			if e != nil {
				return
			}
			defer c.Close()
			peersMu.Lock()
			peers = append(peers, c)
			peersMu.Unlock()
			b := bufio.NewReader(c)
			for {
				request, e := b.ReadBytes(10)
				if e != nil || len(request) > 262144 {
					return
				}
				if _, e = g.in.Write(request); e != nil {
					return
				}
				response, e := g.out.ReadBytes(10)
				if e != nil {
					return
				}
				if _, e = c.Write(response); e != nil {
					return
				}
			}
		}(guests[idx], ln)
	}
	wg.Wait()
	close(done)
	return nil
}
func main() {
	syscall.Umask(0077)
	exe, e := os.Executable()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	bin := filepath.Dir(exe)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "__serve":
		if len(os.Args) != 4 {
			usage()
			os.Exit(2)
		}
		e = runServer(os.Args[2], os.Args[3])
	case "demo":
		f := flag.NewFlagSet("demo", flag.ExitOnError)
		out := f.String("out", filepath.Join("runs", time.Now().UTC().Format("20060102T150405.000000000Z")), "new evidence directory")
		runtimeDir := f.String("runtime", "", "private directory of an already running mint and verifier")
		f.Parse(os.Args[2:])
		p, err := filepath.Abs(*out)
		e = err
		if e == nil && *runtimeDir != "" {
			var live any
			var builds M
			live, e = readArtifact(*runtimeDir, "builds.json")
			if e == nil {
				builds, e = manifest(bin)
			}
			if e == nil && !bytesEqual(live, builds) {
				e = errors.New("existing runtime build mismatch")
			}
		}
		if e == nil {
			e = runDemo(bin, p, *runtimeDir)
		}
		if e == nil {
			fmt.Println("Evidence", p)
		}
	case "agent":
		f := flag.NewFlagSet("agent", flag.ExitOnError)
		state := f.String("state", "", "new private state directory")
		f.Parse(os.Args[2:])
		if *state == "" {
			usage()
			os.Exit(2)
		}
		var out string
		out, e = filepath.Abs(*state)
		if e == nil {
			e = runLab(bin, out, "", true)
		}
	case "request":
		f := flag.NewFlagSet("request", flag.ExitOnError)
		state := f.String("state", "", "running local agent directory")
		f.Parse(os.Args[2:])
		if *state == "" || f.NArg() != 1 {
			usage()
			os.Exit(2)
		}
		var proposal any
		proposal, e = parse([]byte(f.Arg(0)))
		if e == nil {
			e = sendProposal(*state, obj(proposal))
		}
	case "runtime":
		f := flag.NewFlagSet("runtime", flag.ExitOnError)
		d := f.String("socket-dir", "", "new private directory for a single attachment")
		f.Parse(os.Args[2:])
		if *d == "" {
			usage()
			os.Exit(2)
		}
		e = runtimeServer(bin, *d)
	case "verify-spend", "verify-refusal", "verify-response", "verify-failure":
		f := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		operator := f.String("operator-key", "", "pinned operator public key")
		ledger := f.String("ledger-key", "", "pinned local ledger public key")
		requestHash := f.String("request-hash", "", "exact original request digest")
		status := f.Int64("status", 0, "actual response HTTP status")
		f.Parse(os.Args[2:])
		if f.NArg() != 1 {
			usage()
			os.Exit(2)
		}
		path := f.Arg(0)
		var v any
		v, e = readArtifact(filepath.Dir(path), filepath.Base(path))
		if e == nil {
			if os.Args[1] == "verify-failure" {
				e = verifyFailureEvidence(bin, obj(v), *operator, *ledger, *requestHash, *status)
				if e == nil {
					fmt.Println("FAILURE VERIFIED: historical gateway assertion; effect state not established")
				}
			} else if os.Args[1] == "verify-response" {
				e = verifyResponseEvidence(bin, obj(v), *operator, *ledger)
				if e == nil {
					fmt.Println("RESPONSE VERIFIED: historical native response proof and signed ledger evidence")
				}
			} else if os.Args[1] == "verify-refusal" {
				var decision M
				decision, e = verifyRefusal(bin, obj(v), *operator, *ledger)
				if e == nil {
					printRefusal(decision)
				}
			} else {
				e = verifySpend(bin, obj(v), *operator, *ledger)
			}
		}
	case "verify-ledger":
		f := flag.NewFlagSet("verify-ledger", flag.ExitOnError)
		key := f.String("ledger-key", "", "pinned ledger public key")
		f.Parse(os.Args[2:])
		if f.NArg() != 1 {
			usage()
			os.Exit(2)
		}
		var b []byte
		b, e = os.ReadFile(f.Arg(0))
		if e == nil && len(b) > 10*1024*1024 {
			e = errors.New("ledger evidence limit")
		}
		if e == nil {
			var v any
			v, e = parse(b)
			if e == nil {
				var result M
				result, e = verifyLedgerRows(v, *key)
				if e == nil {
					fmt.Println(string(canon(result)))
				}
			}
		}
	case "audit":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		e = audit(os.Args[2], false)
	default:
		usage()
		os.Exit(2)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "HTTP6 pilot:", strings.TrimSpace(e.Error()))
		os.Exit(1)
	}
}
func usage() {
	io.WriteString(os.Stderr, "http6-pilot demo [--out new-directory] [--runtime private-directory]\nhttp6-pilot runtime --socket-dir new-private-directory\nhttp6-pilot audit evidence-directory\nhttp6-pilot verify-ledger --ledger-key hex events.json\nhttp6-pilot agent --state new-directory\nhttp6-pilot request --state directory JSON\nhttp6-pilot verify-spend --operator-key hex --ledger-key hex spend-evidence.json\nhttp6-pilot verify-refusal --operator-key hex --ledger-key hex refusal-evidence.json\nhttp6-pilot verify-response --operator-key hex --ledger-key hex response-evidence.json\nhttp6-pilot verify-failure --operator-key hex --ledger-key hex --request-hash hex --status code failure-evidence.json\n")
}
