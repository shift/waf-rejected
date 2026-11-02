package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testServer(t testing.TB) *server {
	t.Helper()
	return testServerWith(t, true)
}

func testServerWith(t testing.TB, earlyBlocking bool) *server {
	t.Helper()
	engine, err := newEngine("../../wasm/coraza_reactor/rules/crs/crs.conf", 64*1024, earlyBlocking)
	if err != nil {
		t.Fatalf("newEngine: %v", err)
	}
	return &server{
		engine:         engine,
		maxBody:        64 * 1024,
		maxHeaderCount: 100,
		maxHeaderBytes: 64 * 1024,
		requestTimeout: 5 * time.Second,
	}
}

func payload(t *testing.T, value map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

func decision(t *testing.T, s *server, value map[string]any) string {
	t.Helper()
	resp := s.evaluate(payload(t, value))
	return resp.Decision
}

func base(uri string) map[string]any {
	return map[string]any{
		"method":       "GET",
		"uri":          uri,
		"http_version": "HTTP/1.1",
		"headers":      [][2]string{{"host", "example.test"}},
	}
}

func form(method, uri, body string) map[string]any {
	return map[string]any{
		"method":        method,
		"uri":           uri,
		"http_version":  "HTTP/1.1",
		"headers":       [][2]string{{"host", "example.test"}, {"content-type", "application/x-www-form-urlencoded"}},
		"body":          body,
		"body_size":     len(body),
		"body_encoding": "utf8",
	}
}

func TestDecisionParity(t *testing.T) {
	s := testServer(t)
	cases := []struct {
		name string
		req  map[string]any
		want string
	}{
		{"benign", form("POST", "/hello", "name=world&ok=1"), "allow"},
		{"sqli", form("POST", "/login", "user=admin' OR '1'='1' --"), "block"},
		{"sqli-uri", base("/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users"), "block"},
		{"xss", form("POST", "/comment", "text=<script>alert(document.cookie)</script>"), "block"},
		{"xss-uri", base("/search?q=%3Cscript%3Ealert(1)%3C/script%3E"), "block"},
		{"traversal", base("/download?file=../../../../etc/passwd"), "block"},
		{"traversal-body", form("POST", "/download", "file=..%2F..%2F..%2Fetc%2Fpasswd"), "block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decision(t, s, tc.req); got != tc.want {
				t.Fatalf("decision = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMalformedPayloadsFailClosed(t *testing.T) {
	s := testServer(t)
	cases := map[string][]byte{
		"not-json":       []byte("{"),
		"bad-body-b64":   payload(t, map[string]any{"method": "POST", "uri": "/", "body_b64": "!!!"}),
		"bad-encoding":   payload(t, map[string]any{"method": "POST", "uri": "/", "body": "x", "body_encoding": "utf16"}),
		"size-mismatch":  payload(t, map[string]any{"method": "POST", "uri": "/", "body": "abcd", "body_size": 2}),
		"body-too-large": payload(t, map[string]any{"method": "POST", "uri": "/", "body": strings.Repeat("a", 70000)}),
		"headers-too-many": payload(t, map[string]any{
			"method": "GET", "uri": "/",
			"headers": equalHeaders(101),
		}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			resp := s.evaluate(raw)
			if resp.Decision != "block" {
				t.Fatalf("malformed payload was not blocked: %+v", resp)
			}
			if resp.Status != 400 && resp.Status != 413 {
				t.Fatalf("unexpected status %d (%s)", resp.Status, resp.Reason)
			}
		})
	}
}

func equalHeaders(n int) [][2]string {
	out := make([][2]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, [2]string{"x-test", "value"})
	}
	return out
}

func TestConnectionCleanup(t *testing.T) {
	s := testServer(t)
	before := runtime.NumGoroutine()
	req := payload(t, form("POST", "/hello", "name=world"))

	for i := 0; i < 50; i++ {
		serverConn, clientConn := net.Pipe()
		done := make(chan struct{})
		go func() {
			s.handle(serverConn)
			close(done)
		}()

		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(req)))
		if _, err := clientConn.Write(hdr[:]); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := clientConn.Write(req); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		if _, err := readFrame(clientConn); err != nil {
			t.Fatalf("read response: %v", err)
		}
		_ = clientConn.Close()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("connection handler did not exit after client close")
		}
	}

	s.conns.Range(func(key, _ any) bool {
		t.Fatalf("connection %v leaked in server map", key)
		return false
	})

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines leaked: before=%d after=%d", before, after)
	}
}

func TestBodyB64Alias(t *testing.T) {
	s := testServer(t)
	req := map[string]any{
		"method":       "POST",
		"uri":          "/login",
		"http_version": "HTTP/1.1",
		"headers":      [][2]string{{"host", "example.test"}, {"content-type", "application/x-www-form-urlencoded"}},
		"body_b64":     "dXNlcj1hZG1pbiUnIE9SICcxJz0nMScgLS0=",
		"body_size":    24,
	}
	if got := decision(t, s, req); got != "block" {
		t.Fatalf("body_b64 SQLi decision = %q, want block", got)
	}
}
