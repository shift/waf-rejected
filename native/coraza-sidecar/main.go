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
		maxConns       = flag.Int("max-conns", 128, "maximum concurrently served connections")
		timeout        = flag.Duration("timeout", 5*time.Second, "per-request wall-clock budget")
		grace          = flag.Duration("grace", 10*time.Second, "graceful shutdown drain budget")
		earlyBlocking  = flag.Bool("early-blocking", true, "enable CRS phase-1 early blocking (rule 900120) so requests already over the anomaly threshold are denied before the body is scanned")
	)
	flag.Parse()

	engine, err := newEngine(*rulesPath, *maxBody, *earlyBlocking)
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

	log.Printf("ready socket=%s rules=%s max_body=%d max_conns=%d timeout=%s",
		*socketPath, *rulesPath, *maxBody, *maxConns, *timeout)

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

	// Admission control: a connection slot is held for the lifetime of the
	// connection, so the number of concurrently evaluating goroutines is
	// bounded by --max-conns. Blocking here applies backpressure through the
	// listen backlog instead of spawning unbounded goroutines.
	slots := make(chan struct{}, *maxConns)

accept:
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
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			break accept
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
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
//
// earlyBlocking enables CRS rule 900120 (tx.early_blocking=1). Phase-1 rules
// (scanner detection, protocol enforcement, header/cookie attack rules) then
// deny a request as soon as its phase-1 anomaly score reaches the threshold,
// instead of scanning the whole request body first and denying in phase 2.
// The block decision is identical because the phase-1 score is already over
// the threshold; only phase-2 telemetry is skipped, which is the documented
// CRS tradeoff for this mode.
func newEngine(rulesPath string, maxBody int, earlyBlocking bool) (coraza.WAF, error) {
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
	if earlyBlocking {
		preamble += `SecAction "id:900120,phase:1,pass,nolog,t:none,setvar:tx.early_blocking=1"
`
	}
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

	reader := &frameReader{r: conn}
	// Reused response buffer: the steady-state allow path allocates nothing.
	var respBuf []byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.requestTimeout + 5*time.Second))
		frame, err := reader.next()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("read frame: %v", err)
			}
			return
		}
		if isHandshake(frame) {
			var ack [7]byte
			binary.BigEndian.PutUint32(ack[:4], 3)
			ack[4] = frameMagicHandshake
			ack[5] = wireVersion
			ack[6] = 1 // binary v1 supported
			_ = conn.SetWriteDeadline(time.Now().Add(s.requestTimeout))
			if _, err := conn.Write(ack[:]); err != nil {
				log.Printf("write handshake: %v", err)
				return
			}
			continue
		}

		binaryProto := len(frame) > 0 && frame[0] == frameMagicBinary
		resp := s.evaluate(frame)
		_ = conn.SetWriteDeadline(time.Now().Add(s.requestTimeout))
		respBuf, err = writeResponse(conn, respBuf, binaryProto, resp)
		if err != nil {
			log.Printf("write response: %v", err)
			return
		}
	}
}

// writeResponse encodes resp as either a binary v1 or legacy JSON frame into
// buf (reused across requests) and writes it with a single syscall.
func writeResponse(conn net.Conn, buf []byte, binaryProto bool, resp Response) ([]byte, error) {
	buf = buf[:0]
	buf = append(buf, 0, 0, 0, 0)
	if binaryProto {
		buf = appendBinaryResponse(buf, resp)
	} else {
		body, err := json.Marshal(resp)
		if err != nil {
			return buf, err
		}
		buf = append(buf, body...)
	}
	binary.BigEndian.PutUint32(buf[:4], uint32(len(buf)-4))
	_, err := conn.Write(buf)
	return buf, err
}

func readFrame(r io.Reader) ([]byte, error) {
	reader := &frameReader{r: r}
	return reader.next()
}

// evaluate dispatches on the frame magic. The JSON path is retained verbatim
// for compatibility with clients that predate the binary encoding.
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

	var req *wireRequest
	if len(payload) > 0 && payload[0] == frameMagicBinary {
		decoded, err := decodeBinaryRequest(payload)
		if err != nil {
			return Response{Decision: "block", Status: 400,
				Reason: "malformed request payload: " + err.Error()}
		}
		req = decoded
	} else {
		decoded, err := decodeJSONRequest(payload)
		if err != nil {
			return Response{Decision: "block", Status: 400, Reason: err.Error()}
		}
		req = decoded
	}
	return s.evaluateParsed(req)
}

// evaluateParsed applies the limits and runs the CRS transaction. It is shared
// by the JSON and binary decoders so both paths make identical decisions.
func (s *server) evaluateParsed(req *wireRequest) Response {
	if req.BodySize < 0 || req.BodySize > s.maxBody {
		return Response{Decision: "block", Status: 413, Reason: "request body exceeds sidecar limit"}
	}
	if len(req.Headers) > s.maxHeaderCount {
		return Response{Decision: "block", Status: 400,
			Reason: fmt.Sprintf("header count %d exceeds limit %d", len(req.Headers), s.maxHeaderCount)}
	}
	total := 0
	for _, h := range req.Headers {
		total += len(h[0]) + len(h[1])
	}
	if total > s.maxHeaderBytes {
		return Response{Decision: "block", Status: 400,
			Reason: fmt.Sprintf("header bytes %d exceed limit %d", total, s.maxHeaderBytes)}
	}
	if req.HasBody {
		if req.BodySize != len(req.Body) {
			return Response{Decision: "block", Status: 400, Reason: "body_size does not match decoded body"}
		}
		if len(req.Body) > s.maxBody {
			return Response{Decision: "block", Status: 413,
				Reason: fmt.Sprintf("body of %d bytes exceeds limit %d", len(req.Body), s.maxBody)}
		}
	}

	tx := s.engine.NewTransaction()
	defer tx.Close()

	if req.HTTPVersion != "" {
		tx.ProcessURI(req.URI, req.Method, req.HTTPVersion)
	} else {
		tx.ProcessURI(req.URI, req.Method, "HTTP/1.1")
	}
	for _, h := range req.Headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return blockResponse(it, "request headers")
	}
	if len(req.Body) > 0 {
		if _, _, err := tx.WriteRequestBody(req.Body); err != nil {
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

// decodeJSONRequest converts the legacy JSON envelope into the shared
// wireRequest representation.
func decodeJSONRequest(payload []byte) (*wireRequest, error) {
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, errors.New("malformed request payload")
	}
	headers, err := decodeHeaders(req.Headers)
	if err != nil {
		return nil, err
	}
	body, hasBody, err := decodeBody(&req)
	if err != nil {
		return nil, err
	}
	bodySize := len(body)
	if req.BodySize != nil {
		bodySize = *req.BodySize
	}
	return &wireRequest{
		Method:      req.Method,
		URI:         req.URI,
		HTTPVersion: req.HTTPVersion,
		Headers:     headers,
		Body:        body,
		HasBody:     hasBody,
		BodySize:    bodySize,
	}, nil
}

func decodeHeaders(raw json.RawMessage) ([][2]string, error) {
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
	return pairs, nil
}

// decodeBody returns the raw body bytes. Limits and the body_size consistency
// check are applied by evaluateParsed, so both wire encodings share them.
func decodeBody(req *Request) ([]byte, bool, error) {
	if req.BodyB64 != nil {
		if req.Body != nil {
			return nil, false, errors.New("body and body_b64 are mutually exclusive")
		}
		decoded, err := base64.StdEncoding.DecodeString(*req.BodyB64)
		if err != nil {
			return nil, false, errors.New("invalid body_b64")
		}
		return decoded, true, nil
	}
	if req.Body == nil {
		return nil, false, nil
	}
	encoding := req.BodyEncoding
	if encoding == "" {
		encoding = bodyEncodingUTF8
	}
	switch encoding {
	case bodyEncodingUTF8:
		return []byte(*req.Body), true, nil
	case bodyEncodingBase64:
		decoded, err := base64.StdEncoding.DecodeString(*req.Body)
		if err != nil {
			return nil, false, errors.New("invalid base64 body")
		}
		return decoded, true, nil
	default:
		return nil, false, fmt.Errorf("unknown body_encoding %q", encoding)
	}
}

func init() {
	// Same GC tuning rationale as the WASI reactor: CRS allocates ~0.5-1 MiB
	// per 8 KiB body, so an early collection landing mid-evaluation inflates
	// tail latency. A soft memory limit bounds resident growth.
	debug.SetGCPercent(600)
	debug.SetMemoryLimit(192 << 20)
}
