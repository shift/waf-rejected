// Command coraza-sidecar runs the OWASP CRS/Coraza engine natively and exposes
// it to the WAF over a Unix domain socket. It reuses the vendored Coraza module
// and CRS bundle under wasm/coraza_reactor/, so the ruleset is identical to the
// WASI reactor. The process is deliberately foreground-only and logs to stderr
// so it can run under systemd without a supervisor shim.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	// maxFrame bounds the JSON envelope before the body/header limits are
	// applied. It also protects the decoder from unbounded allocation.
	maxFrame = 16 << 20

	bodyEncodingUTF8   = "utf8"
	bodyEncodingBase64 = "base64"
)

// Request is the wire payload. It deliberately mirrors the WASI reactor ABI
// (src/waf/wasm_reactor.rs) so the same request builder can drive either
// backend. body_b64 is accepted as a convenience alias for body +
// body_encoding=base64.
type Request struct {
	Method       string          `json:"method"`
	URI          string          `json:"uri"`
	HTTPVersion  string          `json:"http_version"`
	Headers      json.RawMessage `json:"headers"`
	Body         *string         `json:"body"`
	BodyB64      *string         `json:"body_b64"`
	BodySize     *int            `json:"body_size"`
	BodyEncoding string          `json:"body_encoding"`
}

type Response struct {
	Decision string `json:"decision"`
	Status   int    `json:"status,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type server struct {
	engine         coraza.WAF
	maxBody        int
	maxHeaderCount int
	maxHeaderBytes int
	requestTimeout time.Duration
	conns          sync.Map
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("coraza-sidecar: ")

	var (
		socketPath     = flag.String("socket", "/run/waf/coraza.sock", "Unix domain socket path")
		rulesPath      = flag.String("rules", "wasm/coraza_reactor/rules/crs/crs.conf", "path to crs.conf")
		maxBody        = flag.Int("max-body", 64*1024, "maximum inspected request body in bytes")
		maxHeaders     = flag.Int("max-headers", 100, "maximum number of request headers")
		maxHeaderBytes = flag.Int("max-header-bytes", 64*1024, "maximum total request header bytes")
		timeout        = flag.Duration("timeout", 5*time.Second, "per-request wall-clock budget")
		grace          = flag.Duration("grace", 10*time.Second, "graceful shutdown drain budget")
	)
	flag.Parse()

	engine, err := newEngine(*rulesPath, *maxBody)
	if err != nil {
		log.Fatalf("initialise Coraza: %v", err)
	}
	srv := &server{
		engine:         engine,
		maxBody:        *maxBody,
		maxHeaderCount: *maxHeaders,
		maxHeaderBytes: *maxHeaderBytes,
		requestTimeout: *timeout,
	}

	if err := os.Remove(*socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("remove stale socket %s: %v", *socketPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o750); err != nil {
		log.Fatalf("create socket directory: %v", err)
	}
	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen on %s: %v", *socketPath, err)
	}
	defer ln.Close()
	if err := os.Chmod(*socketPath, 0o660); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("ready socket=%s rules=%s max_body=%d timeout=%s", *socketPath, *rulesPath, *maxBody, *timeout)

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		// Close idle pooled connections too; otherwise a graceful drain would
		// always wait for the full grace period.
		srv.conns.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("accept: %v", err)
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.handle(conn)
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Print("shutdown complete")
	case <-time.After(*grace):
		log.Print("shutdown grace period expired; exiting with connections open")
	}
}

// newEngine loads the pinned CRS bundle. The data files (@pmFromFile) are
// resolved relative to crs.conf, exactly as the WASI reactor does with its
// embedded rules subtree.
func newEngine(rulesPath string, maxBody int) (coraza.WAF, error) {
	conf, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("read rules %s: %w", rulesPath, err)
	}
	root := filepath.Join(filepath.Dir(rulesPath), "rules")
	rootFS := os.DirFS(root)
	if _, err := fs.Stat(rootFS, "."); err != nil {
		return nil, fmt.Errorf("rules data directory %s: %w", root, err)
	}
	preamble := fmt.Sprintf(`SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecResponseBodyAccess Off
`, maxBody, maxBody)
	return coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(rootFS).
			WithDirectives(strings.TrimSpace(preamble + string(conf))),
	)
}

func (s *server) handle(conn net.Conn) {
	s.conns.Store(conn, struct{}{})
	defer s.conns.Delete(conn)
	defer conn.Close()
	for {
		deadline := time.Now().Add(s.requestTimeout + 5*time.Second)
		_ = conn.SetReadDeadline(deadline)
		payload, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("read frame: %v", err)
			}
			return
		}
		resp := s.evaluate(payload)
		_ = conn.SetWriteDeadline(time.Now().Add(s.requestTimeout))
		if err := writeFrame(conn, resp); err != nil {
			log.Printf("write response: %v", err)
			return
		}
	}
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("frame of %d bytes exceeds %d byte limit", n, maxFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(w io.Writer, resp Response) error {
	body, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func (s *server) evaluate(payload []byte) Response {
	// The sidecar owns the timeout: a slow evaluation is reported to the
	// client as a block rather than leaving the connection hanging. Coraza
	// itself has no cancellation API, so this is an observation deadline.
	start := time.Now()
	defer func() {
		if d := time.Since(start); d > s.requestTimeout {
			log.Printf("evaluation exceeded timeout: %s", d)
		}
	}()

	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return Response{Decision: "block", Status: 400, Reason: "malformed request payload"}
	}
	if req.BodySize != nil && (*req.BodySize < 0 || *req.BodySize > s.maxBody) {
		return Response{Decision: "block", Status: 413, Reason: "request body exceeds sidecar limit"}
	}
	headers, err := s.decodeHeaders(req.Headers)
	if err != nil {
		return Response{Decision: "block", Status: 400, Reason: err.Error()}
	}
	body, err := decodeBody(&req, s.maxBody)
	if err != nil {
		return Response{Decision: "block", Status: 400, Reason: err.Error()}
	}

	tx := s.engine.NewTransaction()
	defer tx.Close()

	if req.HTTPVersion != "" {
		tx.ProcessURI(req.URI, req.Method, req.HTTPVersion)
	} else {
		tx.ProcessURI(req.URI, req.Method, "HTTP/1.1")
	}
	for _, h := range headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return blockResponse(it, "request headers")
	}
	if len(body) > 0 {
		if _, _, err := tx.WriteRequestBody(body); err != nil {
			return Response{Decision: "block", Status: 400, Reason: "invalid request body"}
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		return Response{Decision: "block", Status: 400, Reason: "request body processing failed"}
	} else if it != nil {
		return blockResponse(it, "request body")
	}
	if tx.IsInterrupted() {
		return Response{Decision: "block", Status: 403, Reason: "request blocked by Coraza"}
	}
	return Response{Decision: "allow"}
}

func blockResponse(it *types.Interruption, phase string) Response {
	status := it.Status
	if status == 0 {
		status = 403
	}
	reason := fmt.Sprintf("Coraza blocked %s", phase)
	if it.RuleID != 0 {
		reason = fmt.Sprintf("%s (rule %d)", reason, it.RuleID)
	}
	return Response{Decision: "block", Status: status, Reason: reason}
}

func (s *server) decodeHeaders(raw json.RawMessage) ([][2]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var pairs [][2]string
	if err := json.Unmarshal(raw, &pairs); err != nil {
		var object map[string]string
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, errors.New("malformed headers")
		}
		pairs = make([][2]string, 0, len(object))
		for k, v := range object {
			pairs = append(pairs, [2]string{k, v})
		}
	}
	if len(pairs) > s.maxHeaderCount {
		return nil, fmt.Errorf("header count %d exceeds limit %d", len(pairs), s.maxHeaderCount)
	}
	total := 0
	for _, h := range pairs {
		total += len(h[0]) + len(h[1])
	}
	if total > s.maxHeaderBytes {
		return nil, fmt.Errorf("header bytes %d exceed limit %d", total, s.maxHeaderBytes)
	}
	return pairs, nil
}

func decodeBody(req *Request, maxBody int) ([]byte, error) {
	if req.BodyB64 != nil {
		if req.Body != nil {
			return nil, errors.New("body and body_b64 are mutually exclusive")
		}
		decoded, err := base64.StdEncoding.DecodeString(*req.BodyB64)
		if err != nil {
			return nil, errors.New("invalid body_b64")
		}
		if len(decoded) > maxBody {
			return nil, fmt.Errorf("body of %d bytes exceeds limit %d", len(decoded), maxBody)
		}
		return decoded, nil
	}
	if req.Body == nil {
		return nil, nil
	}
	encoding := req.BodyEncoding
	if encoding == "" {
		encoding = bodyEncodingUTF8
	}
	var body []byte
	switch encoding {
	case bodyEncodingUTF8:
		body = []byte(*req.Body)
	case bodyEncodingBase64:
		decoded, err := base64.StdEncoding.DecodeString(*req.Body)
		if err != nil {
			return nil, errors.New("invalid base64 body")
		}
		body = decoded
	default:
		return nil, fmt.Errorf("unknown body_encoding %q", encoding)
	}
	if req.BodySize != nil && *req.BodySize != len(body) {
		return nil, errors.New("body_size does not match decoded body")
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("body of %d bytes exceeds limit %d", len(body), maxBody)
	}
	return body, nil
}

func init() {
	// Same GC tuning rationale as the WASI reactor: CRS allocates ~0.5-1 MiB
	// per 8 KiB body, so an early collection landing mid-evaluation inflates
	// tail latency. A soft memory limit bounds resident growth.
	debug.SetGCPercent(600)
	debug.SetMemoryLimit(192 << 20)
}
