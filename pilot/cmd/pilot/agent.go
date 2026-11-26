package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type pendingCall struct {
	wire         invocation
	proposalHash string
}
type agentServer struct {
	l    *lab
	db   *database
	open map[string]pendingCall
	mu   sync.Mutex
}

func (l *lab) serveAgent(tmp string) error {
	socket := filepath.Join(tmp, "agent.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer ln.Close()
	if e = os.Chmod(socket, 0600); e != nil {
		return e
	}
	db, e := openDB(filepath.Join(l.out, "agent.sqlite"))
	if e != nil {
		return e
	}
	defer db.close()
	if e = db.exec("CREATE TABLE proposals(id INTEGER PRIMARY KEY,op TEXT,audience TEXT,digest TEXT,verdict TEXT,at TEXT)"); e != nil {
		return e
	}
	a := &agentServer{l: l, db: db, open: map[string]pendingCall{}}
	server := &http.Server{Handler: a, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 4 * time.Second, WriteTimeout: 8 * time.Second, MaxHeaderBytes: 8192}
	config := M{"agent": socket, "broker": l.services["broker"].socket, "ledger": l.services["local-ledger"].socket, "operatorKey": l.trust["operator"], "localLedgerKey": l.trust["localLedgerKey"], "profile": profile}
	if e = artifact(filepath.Join(l.out, "connections.json"), config); e != nil {
		return e
	}
	fmt.Printf("READY local agent %s\n", l.out)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		grace, release := context.WithTimeout(context.Background(), 7*time.Second)
		defer release()
		server.Shutdown(grace)
		close(closed)
	}()
	e = server.Serve(ln)
	cancel()
	<-closed
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func (a *agentServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.RequestURI() != api+"propose" {
		answer(w, nil, deny("UNKNOWN_AGENT_ROUTE"))
		return
	}
	raw, readErr := io.ReadAll(io.LimitReader(r.Body, 65537))
	if readErr != nil || len(raw) > 65536 {
		answer(w, M{"proofStatus": "unavailable"}, &apiError{413, "BODY_LIMIT"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	parsed, e := parse(raw)
	m := obj(parsed)
	if e != nil || m == nil || !bytes.Equal(raw, canon(parsed)) {
		a.answerFailure(w, raw, nil, &apiError{400, "MALFORMED_REQUEST"}, "malformed", 400)
		return
	}
	value, e := a.propose(m)
	verdict := "COMMITTED"
	if e != nil {
		verdict = e.Error()
	}
	if err := a.db.exec("INSERT INTO proposals(op,audience,digest,verdict,at) VALUES(?,?,?,?,?)", st(m, "op"), st(m, "audience"), hash("proposal", m), verdict, fmt.Sprint(stamp())); err != nil {
		a.answerFailure(w, raw, nil, &apiError{503, "AGENT_JOURNAL_UNAVAILABLE"}, "uncertain", 503)
		return
	}
	if e != nil {
		category := "uncertain"
		status := int64(503)
		if strings.Contains(e.Error(), "UNCERTAIN") || strings.Contains(e.Error(), "RESPONSE_PROOF_VERIFICATION_FAILED") {
			category = "uncertain"
			status = 503
		} else {
			var ae *apiError
			if errors.As(e, &ae) && ae.Status >= 500 {
				category = "held"
			} else if errors.As(e, &ae) && ae.Status == 403 {
				category = "denied"
				status = 403
			}
		}
		a.answerFailure(w, raw, value, e, category, status)
		return
	}
	answer(w, value, nil)
}

// The private supervisor asks the broker to attest what this gateway observed.
// A signed failure is not a finding that an action did or did not occur.
func (a *agentServer) answerFailure(w http.ResponseWriter, raw []byte, value any, original error, category string, status int64) {
	core := obj(value)
	if core == nil {
		core = M{}
	} else {
		core = copyMap(core)
	}
	core["error"] = original.Error()
	core["category"] = category
	result := copyMap(core)
	result["failureCore"] = core
	result["proofStatus"] = "unavailable"
	requestHash := sha(raw)
	proved, e := a.l.services["broker"].proveAgentFailure(requestHash, core, category, status)
	if e == nil {
		for k, v := range proved {
			result[k] = v
		}
		if e = verifyFailure(a.l.attestor, a.l.trust, result, requestHash, status, ""); e == nil {
			name := "failure-" + nonce() + ".json"
			if e = a.l.writeFailureEvidence(name, result, requestHash, status); e == nil {
				result["failureEvidenceFile"] = name
				result["proofStatus"] = "ledger-recorded"
			}
		}
	}
	if e != nil {
		delete(result, "failure")
		delete(result, "failureDecision")
		delete(result, "failureEventRef")
	}
	answer(w, result, &apiError{int(status), original.Error()})
}
func (a *agentServer) propose(m M) (reply any, err error) {
	defer func() {
		if v := recover(); v != nil {
			if f, ok := v.(testFailure); ok {
				err = f.err
			} else {
				panic(v)
			}
		}
	}()
	for k := range m {
		switch k {
		case "op", "audience", "resource", "args", "holdSeconds":
		default:
			return nil, deny("UNKNOWN_PROPOSAL_FIELD")
		}
	}
	l := a.l
	aud := st(m, "audience")
	op := st(m, "op")
	if l.children[aud] == nil || op == "" || obj(m["args"]) == nil || st(m, "resource") == "" {
		return nil, deny("PROPOSAL_SHAPE")
	}
	ttl := int64(5)
	if _, ok := m["holdSeconds"]; ok {
		ttl = integer(m, "holdSeconds")
	}
	if ttl < 1 || ttl > 5 {
		return nil, deny("TTL_OUT_OF_RANGE")
	}
	id := aud + "/" + op
	digest := hash("proposal", m)
	pending, ok := a.open[id]
	if ok && pending.proposalHash != digest {
		return nil, deny("OPERATION_CONFLICT")
	}
	if !ok {
		prior, e := a.db.query("SELECT digest,verdict FROM proposals WHERE audience=? AND op=? AND verdict NOT IN ('HELD_RESOURCE','HELD_LEDGER','OPERATION_CONFLICT') ORDER BY id LIMIT 1", aud, op)
		if e != nil {
			return nil, e
		}
		if len(prior) > 0 {
			if prior[0]["digest"] != digest {
				return nil, deny("OPERATION_CONFLICT")
			}
			if prior[0]["verdict"] == "COMMITTED" {
				return nil, deny("SPENT")
			}
			return nil, deny("REJECTED")
		}
		if aud == "wallet" {
			v, e := a.walletReview(m)
			if e != nil {
				return v, e
			}
		}
		i := l.intent(aud, "allowed")
		i["args"] = m["args"]
		i["resource"] = m["resource"]
		x := l.issuePrepared(aud, l.prepareIntent(aud, op, i, int(ttl)))
		pending = pendingCall{x, digest}
		a.open[id] = pending
	}
	v, e := l.send(aud, "broker", "allowed", pending.wire)
	if e != nil {
		// The original signed certificate determines how long the same operation can be retried.
		if stamp() >= integer(peek(pending.wire.certificate), "exp") {
			delete(a.open, id)
		}
		return nil, e
	}
	delete(a.open, id)
	result := obj(v)
	if _, e = verifyResponse(l.attestor, l.trust, pending.wire.wire, result, ""); e != nil {
		return nil, &apiError{503, "RESPONSE_PROOF_VERIFICATION_FAILED"}
	}
	responseFile := "response-" + st(pending.wire.attempt, "record") + ".json"
	if e = l.writeResponseEvidence(responseFile, aud, pending.wire.wire, result); e != nil {
		return nil, e
	}
	result["responseEvidenceFile"] = responseFile
	if aud == "wallet" {
		name := "spend-" + st(pending.wire.attempt, "record") + ".json"
		if e = writeSpend(l.out, name, l.trust, l.families[aud], pending.wire); e != nil {
			return nil, e
		}
		result["evidenceFile"] = name
	}
	return result, nil
}
func sendProposal(state string, m M) error {
	c, e := readArtifact(state, "connections.json")
	if e != nil {
		return e
	}
	s := st(obj(c), "agent")
	if s == "" {
		return errors.New("agent socket unavailable")
	}
	client := postClient("", map[string]string{"agent.local:80": s})
	defer client.CloseIdleConnections()
	v, e := exchange(client, "POST", "http://agent.local"+api+"propose", m, nil)
	if e != nil {
		if obj(v)["evidenceFile"] != nil || obj(v)["failureEvidenceFile"] != nil {
			fmt.Println(string(canon(v)))
		}
		return e
	}
	fmt.Println(string(canon(v)))
	return nil
}
