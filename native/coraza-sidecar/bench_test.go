package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Benchmarks that split the sidecar's per-request cost into decode, Coraza
// evaluation and response encode. Run with:
//
//	go test -run '^$' -bench . -benchmem ./...
//
// The sizes match the documented latency matrix (1/4/8/16 KiB).

func benchSizes() []int { return []int{1 << 10, 4 << 10, 8 << 10, 16 << 10} }

func benchFormBody(size int) []byte {
	body := make([]byte, 0, size)
	body = append(body, "data="...)
	for len(body) < size {
		body = append(body, 'A')
	}
	return body
}

func benchJSONPayload(tb testing.TB, size int) []byte {
	tb.Helper()
	body := benchFormBody(size)
	encoded, err := json.Marshal(map[string]any{
		"method":        "POST",
		"uri":           "/submit",
		"http_version":  "HTTP/1.1",
		"headers":       [][2]string{{"host", "bench.test"}, {"content-type", "application/x-www-form-urlencoded"}},
		"body":          string(body),
		"body_size":     len(body),
		"body_encoding": "utf8",
	})
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	return encoded
}

func benchWireRequest(size int) *wireRequest {
	body := benchFormBody(size)
	return &wireRequest{
		Method:      "POST",
		URI:         "/submit",
		HTTPVersion: "HTTP/1.1",
		Headers: [][2]string{
			{"host", "bench.test"},
			{"content-type", "application/x-www-form-urlencoded"},
		},
		Body:     body,
		HasBody:  true,
		BodySize: len(body),
	}
}

func BenchmarkDecodeJSON(b *testing.B) {
	for _, size := range benchSizes() {
		payload := benchJSONPayload(b, size)
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				req, err := decodeJSONRequest(payload)
				if err != nil {
					b.Fatal(err)
				}
				_ = req
			}
		})
	}
}

func BenchmarkDecodeBinary(b *testing.B) {
	for _, size := range benchSizes() {
		frame := appendBinaryRequest(nil, benchWireRequest(size))
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				req, err := decodeBinaryRequest(frame)
				if err != nil {
					b.Fatal(err)
				}
				_ = req
			}
		})
	}
}

func BenchmarkEncodeResponse(b *testing.B) {
	allow := Response{Decision: "allow"}
	block := Response{Decision: "block", Status: 403, Reason: "Coraza blocked request body (rule 942100)"}
	b.Run("json/allow", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := json.Marshal(allow); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("json/block", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := json.Marshal(block); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("binary/allow", func(b *testing.B) {
		buf := make([]byte, 0, 128)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf = appendBinaryResponse(buf[:0], allow)
		}
	})
	b.Run("binary/block", func(b *testing.B) {
		buf := make([]byte, 0, 128)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf = appendBinaryResponse(buf[:0], block)
		}
	})
}

// BenchmarkEvaluate isolates the CRS transaction cost (no wire encoding).
func BenchmarkEvaluate(b *testing.B) {
	s := testServer(b)
	for _, size := range benchSizes() {
		req := benchWireRequest(size)
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(len(req.Body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if resp := s.evaluateParsed(req); resp.Decision != "allow" {
					b.Fatalf("unexpected decision: %+v", resp)
				}
			}
		})
	}
}

// BenchmarkFrame measures decode + CRS evaluation + encode for each encoding,
// i.e. everything the sidecar does per request except the socket syscalls.
func BenchmarkFrame(b *testing.B) {
	s := testServer(b)
	for _, size := range benchSizes() {
		label := fmt.Sprintf("%dKiB", size>>10)
		jsonPayload := benchJSONPayload(b, size)
		binaryPayload := appendBinaryRequest(nil, benchWireRequest(size))

		b.Run("json/"+label, func(b *testing.B) {
			b.SetBytes(int64(len(jsonPayload)))
			b.ReportAllocs()
			buf := make([]byte, 0, 128)
			for i := 0; i < b.N; i++ {
				buf = writeResponseBuf(buf, false, s.evaluate(jsonPayload))
			}
			_ = buf
		})
		b.Run("binary/"+label, func(b *testing.B) {
			b.SetBytes(int64(len(binaryPayload)))
			b.ReportAllocs()
			buf := make([]byte, 0, 128)
			for i := 0; i < b.N; i++ {
				buf = writeResponseBuf(buf, true, s.evaluate(binaryPayload))
			}
			_ = buf
		})
	}
}

// writeResponseBuf mirrors writeResponse without the socket write so the
// benchmark measures encoding only.
func writeResponseBuf(buf []byte, binaryProto bool, resp Response) []byte {
	buf = buf[:0]
	buf = append(buf, 0, 0, 0, 0)
	if binaryProto {
		return appendBinaryResponse(buf, resp)
	}
	body, _ := json.Marshal(resp)
	return append(buf, body...)
}

// BenchmarkEvaluateEarlyBlocking measures a request that phase-1 rules already
// block (scanner User-Agent) while it carries an 8 KiB body. With CRS early
// blocking the body is never scanned; without it the full CRS body phase runs
// before the phase-2 anomaly check denies the request.
func BenchmarkEvaluateEarlyBlocking(b *testing.B) {
	req := benchWireRequest(8 << 10)
	req.Headers = append(req.Headers,
		[2]string{"user-agent", "sqlmap/1.7.2#stable (https://sqlmap.org)"})

	for _, tc := range []struct {
		name string
		srv  *server
	}{
		{"early-blocking", testServerWith(b, true)},
		{"phase-2-only", testServerWith(b, false)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(req.Body)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if resp := tc.srv.evaluateParsed(req); resp.Decision != "block" {
					b.Fatalf("unexpected decision: %+v", resp)
				}
			}
		})
	}
}
