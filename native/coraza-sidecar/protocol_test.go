package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func binaryFrame(req *wireRequest) []byte {
	payload := appendBinaryRequest(nil, req)
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

func requestFromJSON(t *testing.T, value map[string]any) *wireRequest {
	t.Helper()
	req, err := decodeJSONRequest(payload(t, value))
	if err != nil {
		t.Fatalf("decodeJSONRequest: %v", err)
	}
	return req
}

func TestBinaryRequestRoundTrip(t *testing.T) {
	req := &wireRequest{
		Method:       "POST",
		URI:          "/submit?q=1",
		HTTPVersion:  "HTTP/1.1",
		Headers:      [][2]string{{"host", "example.test"}, {"content-type", "application/x-www-form-urlencoded"}},
		Body:         []byte("name=world&ok=1"),
		HasBody:      true,
		BodySize:     len("name=world&ok=1"),
		OriginalSize: len("name=world&ok=1"),
		Truncated:    false,
	}
	frame := appendBinaryRequest(nil, req)
	got, err := decodeBinaryRequest(frame)
	if err != nil {
		t.Fatalf("decodeBinaryRequest: %v", err)
	}
	if got.Method != req.Method || got.URI != req.URI || got.HTTPVersion != req.HTTPVersion {
		t.Fatalf("request line mismatch: %+v", got)
	}
	if len(got.Headers) != len(req.Headers) {
		t.Fatalf("header count = %d, want %d", len(got.Headers), len(req.Headers))
	}
	for i := range req.Headers {
		if got.Headers[i] != req.Headers[i] {
			t.Fatalf("header %d = %v, want %v", i, got.Headers[i], req.Headers[i])
		}
	}
	if !got.HasBody || !bytes.Equal(got.Body, req.Body) || got.BodySize != len(req.Body) {
		t.Fatalf("body mismatch: %+v", got)
	}
	if got.OriginalSize != req.OriginalSize {
		t.Fatalf("original size = %d, want %d", got.OriginalSize, req.OriginalSize)
	}
}

func TestBinaryRequestRoundTripBinaryBody(t *testing.T) {
	// Invalid UTF-8 must survive the binary path byte-for-byte; the JSON path
	// base64-encodes it for exactly the same reason.
	raw := []byte{0x00, 0xff, 0xfe, 0x01, 0x80}
	req := &wireRequest{
		Method:      "POST",
		URI:         "/grpc",
		HTTPVersion: "HTTP/2",
		Headers:     [][2]string{{"content-type", "application/grpc+proto"}},
		Body:        raw,
		HasBody:     true,
		BodySize:    len(raw),
	}
	got, err := decodeBinaryRequest(appendBinaryRequest(nil, req))
	if err != nil {
		t.Fatalf("decodeBinaryRequest: %v", err)
	}
	if !bytes.Equal(got.Body, raw) {
		t.Fatalf("binary body corrupted: %v", got.Body)
	}
}

func TestBinaryResponseRoundTrip(t *testing.T) {
	cases := []Response{
		{Decision: "allow"},
		{Decision: "block", Status: 403, Reason: "Coraza blocked request body (rule 942100)"},
		{Decision: "block", Status: 413, Reason: "request body exceeds sidecar limit"},
	}
	for _, want := range cases {
		frame := appendBinaryResponse(nil, want)
		if want.Decision == "allow" && len(frame) != binaryResponseHeaderLen {
			t.Fatalf("allow response is %d bytes, want %d", len(frame), binaryResponseHeaderLen)
		}
		got, err := decodeBinaryResponse(frame)
		if err != nil {
			t.Fatalf("decodeBinaryResponse(%v): %v", want, err)
		}
		if got != want {
			t.Fatalf("response = %+v, want %+v", got, want)
		}
	}
}

func TestBinaryMalformedFrames(t *testing.T) {
	good := appendBinaryRequest(nil, &wireRequest{
		Method: "GET", URI: "/", HTTPVersion: "HTTP/1.1",
		Headers: [][2]string{{"host", "example.test"}},
	})
	corrupt := func(mutate func([]byte) []byte) []byte {
		buf := append([]byte(nil), good...)
		return mutate(buf)
	}
	cases := map[string][]byte{
		"empty":              {},
		"short-header":       good[:binaryRequestHeaderLen-1],
		"bad-version":        corrupt(func(b []byte) []byte { b[1] = 9; return b }),
		"trailing-byte":      append(append([]byte(nil), good...), 0),
		"truncated-body":     good[:len(good)-1],
		"body-flag-mismatch": corrupt(func(b []byte) []byte { b[2] |= flagHasBody; return b }),
		"header-count-lies": corrupt(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[10:12], 200)
			return b
		}),
		"blob-length-lies": corrupt(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[24:28], 1<<20)
			return b
		}),
		"huge-body-length": corrupt(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[12:16], 0xfffffff0)
			return b
		}),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBinaryRequest(frame); err == nil {
				t.Fatalf("malformed frame decoded without error")
			}
		})
	}
}

func TestBinaryMalformedFrameFailsClosed(t *testing.T) {
	s := testServer(t)
	frame := append([]byte{frameMagicBinary, wireVersion, 0, 0}, make([]byte, binaryRequestHeaderLen)...)
	frame[1] = 99 // unsupported version
	resp := s.evaluate(frame)
	if resp.Decision != "block" || resp.Status != 400 {
		t.Fatalf("malformed binary frame was not blocked: %+v", resp)
	}
}

func TestBinaryDecisionParity(t *testing.T) {
	s := testServer(t)
	cases := []struct {
		name string
		req  map[string]any
	}{
		{"benign", form("POST", "/hello", "name=world&ok=1")},
		{"sqli", form("POST", "/login", "user=admin' OR '1'='1' --")},
		{"sqli-uri", base("/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users")},
		{"xss", form("POST", "/comment", "text=<script>alert(document.cookie)</script>")},
		{"traversal", base("/download?file=../../../../etc/passwd")},
		{"get-no-body", base("/hello?id=42")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jsonResp := s.evaluate(payload(t, tc.req))
			binaryResp := s.evaluate(appendBinaryRequest(nil, requestFromJSON(t, tc.req)))
			if jsonResp.Decision != binaryResp.Decision {
				t.Fatalf("decision parity: json=%+v binary=%+v", jsonResp, binaryResp)
			}
			if jsonResp.Status != binaryResp.Status {
				t.Fatalf("status parity: json=%+v binary=%+v", jsonResp, binaryResp)
			}
		})
	}
}

func TestBinaryBodySizeLimits(t *testing.T) {
	s := testServer(t)
	req := requestFromJSON(t, form("POST", "/hello", strings.Repeat("a", 70000)))
	resp := s.evaluate(appendBinaryRequest(nil, req))
	if resp.Decision != "block" || resp.Status != 413 {
		t.Fatalf("oversized binary body was not rejected: %+v", resp)
	}

	tooMany := requestFromJSON(t, map[string]any{
		"method": "GET", "uri": "/", "headers": equalHeaders(101),
	})
	resp = s.evaluate(appendBinaryRequest(nil, tooMany))
	if resp.Decision != "block" || resp.Status != 400 {
		t.Fatalf("too many binary headers were not rejected: %+v", resp)
	}
}

func TestBinaryFramePartialReads(t *testing.T) {
	req := &wireRequest{
		Method: "POST", URI: "/submit", HTTPVersion: "HTTP/1.1",
		Headers: [][2]string{{"host", "example.test"}},
		Body:    bytes.Repeat([]byte("a"), 4096), HasBody: true, BodySize: 4096,
	}
	frame := binaryFrame(req)

	client, serverConn := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		reader := &frameReader{r: serverConn}
		got, err := reader.next()
		if err != nil {
			done <- nil
			return
		}
		done <- got
	}()
	// One byte at a time: the reader must reassemble the frame.
	for _, b := range frame {
		if _, err := client.Write([]byte{b}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	select {
	case got := <-done:
		if !bytes.Equal(got, frame[4:]) {
			t.Fatalf("reassembled frame mismatch (%d vs %d bytes)", len(got), len(frame)-4)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial frame was not reassembled")
	}
	_ = client.Close()
}

func TestPipelinedBinaryFrames(t *testing.T) {
	s := testServer(t)
	client, serverConn := net.Pipe()
	go s.handle(serverConn)

	const pipelined = 8
	go func() {
		req := appendBinaryRequest(nil, requestFromJSON(t, form("POST", "/hello", "name=world")))
		var buf bytes.Buffer
		for i := 0; i < pipelined; i++ {
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], uint32(len(req)))
			buf.Write(hdr[:])
			buf.Write(req)
		}
		_, _ = client.Write(buf.Bytes())
	}()

	reader := &frameReader{r: client}
	for i := 0; i < pipelined; i++ {
		frame, err := reader.next()
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		resp, err := decodeBinaryResponse(frame)
		if err != nil {
			t.Fatalf("decode response %d: %v", i, err)
		}
		if resp.Decision != "allow" {
			t.Fatalf("response %d = %+v, want allow", i, resp)
		}
	}
	_ = client.Close()
}

func TestHandshakeNegotiation(t *testing.T) {
	s := testServer(t)
	client, serverConn := net.Pipe()
	go s.handle(serverConn)
	defer client.Close()

	handshake := []byte{0, 0, 0, 2, frameMagicHandshake, wireVersion}
	if _, err := client.Write(handshake); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	reader := &frameReader{r: client}
	frame, err := reader.next()
	if err != nil {
		t.Fatalf("read handshake ack: %v", err)
	}
	if !isHandshake(frame) || frame[1] != wireVersion || frame[2] != 1 {
		t.Fatalf("unexpected handshake ack: %v", frame)
	}

	// The connection stays usable for binary requests after negotiation.
	req := appendBinaryRequest(nil, requestFromJSON(t, base("/hello")))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(req)))
	if _, err := client.Write(append(hdr[:], req...)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	frame, err = reader.next()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp, err := decodeBinaryResponse(frame); err != nil || resp.Decision != "allow" {
		t.Fatalf("post-handshake response = %+v, %v", resp, err)
	}
}

func TestLegacyJSONStillAccepted(t *testing.T) {
	s := testServer(t)
	client, serverConn := net.Pipe()
	go s.handle(serverConn)
	defer client.Close()

	body := payload(t, form("POST", "/hello", "name=world"))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := client.Write(append(hdr[:], body...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	frame, err := readFrame(client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(frame, &resp); err != nil {
		t.Fatalf("legacy JSON response was not JSON: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("legacy response = %+v", resp)
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	client, serverConn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		reader := &frameReader{r: serverConn}
		_, err := reader.next()
		done <- err
	}()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxFrame+1)
	if _, err := client.Write(hdr[:]); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversized frame error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("oversized frame was not rejected")
	}
	_ = client.Close()
}

func TestFrameReaderReusesBuffer(t *testing.T) {
	req := &wireRequest{Method: "GET", URI: "/", HTTPVersion: "HTTP/1.1"}
	payload := appendBinaryRequest(nil, req)
	var stream bytes.Buffer
	for i := 0; i < 3; i++ {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
		stream.Write(hdr[:])
		stream.Write(payload)
	}
	reader := &frameReader{r: &stream}
	first, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	firstPtr := &first[:1][0]
	for i := 1; i < 3; i++ {
		frame, err := reader.next()
		if err != nil {
			t.Fatalf("next %d: %v", i, err)
		}
		if &frame[:1][0] != firstPtr {
			t.Fatalf("frame %d used a new buffer", i)
		}
	}
}
