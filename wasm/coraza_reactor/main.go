//go:build wasip1 && wasm

// Package main implements a Coraza-based WASI reactor for the WAF-Rejected
// host ABI. It is intentionally a reactor (c-shared) rather than the
// historical GOOS=js command module: there is no JavaScript bridge and no
// dependency on files under rules/ at runtime.
package main

import (
	"encoding/json"
	"strings"
	"unsafe"

	"github.com/corazawaf/coraza/v3"
)

// maxInputBytes is the size of the static request buffer exposed to the host.
// Keep this in sync with the host's DEFAULT_MAX_PAYLOAD_BYTES and the input
// buffer size documented in docs/coraza-wasi-reactor.md.
const maxInputBytes = 64 * 1024

// Explicit, minimal rule set. These are deliberately small and readable so
// the reactor can be audited; OWASP CRS is future work.
const embeddedRules = `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 131072
SecRequestBodyInMemoryLimit 131072
SecResponseBodyAccess Off
SecRule REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS|ARGS "@rx (?i)(?:union[\s/*]+select|select[\s/*]+.*from|insert[\s/*]+into|update[\s/*]+set|delete[\s/*]+from|drop[\s/*]+table|information_schema|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|['\x22]\s*or\s+['\x22]?1['\x22]?\s*=\s*['\x22]?1)" "id:1001,phase:2,deny,status:403,log,msg:'SQL injection detected',tag:'attack-sqli'"
SecRule REQUEST_URI|REQUEST_BODY|REQUEST_HEADERS|ARGS "@rx (?i)(?:<\s*script|javascript\s*:|vbscript\s*:|on(?:load|error|click|mouseover)\s*=|<iframe|<object|<embed|<svg[\s/>])" "id:1002,phase:2,deny,status:403,log,msg:'XSS detected',tag:'attack-xss'"
SecRule REQUEST_URI|REQUEST_BODY|ARGS|REQUEST_HEADERS "@rx (?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f)" "id:1003,phase:2,deny,status:403,log,msg:'Path traversal detected',tag:'attack-lfi'"
SecRule REQUEST_BODY "@rx (?:^|[\x26])(?:cmd|exec|command)=.*(?:;|\||\x60|\$\(|%0a|%0d)" "id:1004,phase:2,deny,status:403,log,msg:'Command injection detected',tag:'attack-rce'"
`

// inputBuf is static storage whose address is advertised through input_base.
// It must never move (Go's GC is non-moving for this kind of global), so the
// host may keep using the returned offset for the lifetime of the instance.
var inputBuf [maxInputBytes]byte

var (
	engine  coraza.WAF
	initErr error
)

// Request is the JSON payload shape produced by src/waf/wasm_reactor.rs.
// Headers are accepted both as [[name, value], ...] (the host's current
// form) and as {"name": "value"} for manual testing.
type Request struct {
	Method      string          `json:"method"`
	URI         string          `json:"uri"`
	HTTPVersion string          `json:"http_version"`
	Headers     json.RawMessage `json:"headers"`
	Body        *string         `json:"body"`
	BodySize    int             `json:"body_size"`
}

func decodeHeaders(raw json.RawMessage) [][2]string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var pairs [][2]string
	if err := json.Unmarshal(raw, &pairs); err == nil {
		return pairs
	}
	var object map[string]string
	if err := json.Unmarshal(raw, &object); err == nil {
		out := make([][2]string, 0, len(object))
		for k, v := range object {
			out = append(out, [2]string{k, v})
		}
		return out
	}
	return nil
}

func ensureEngine() {
	if engine != nil || initErr != nil {
		return
	}
	engine, initErr = coraza.NewWAF(
		coraza.NewWAFConfig().WithDirectives(strings.TrimSpace(embeddedRules)),
	)
}

//go:wasmexport input_base
func inputBase() int32 {
	return int32(uintptr(unsafe.Pointer(&inputBuf[0])))
}

//go:wasmexport init
func wafInit() int32 {
	ensureEngine()
	if initErr != nil {
		return 1
	}
	return 0
}

//go:wasmexport eval
func wafEval(ptr int32, length int32) int32 {
	if engine == nil {
		ensureEngine()
		if initErr != nil {
			return -1
		}
	}
	if length < 0 || int(length) > maxInputBytes {
		return -3
	}
	if ptr < 0 {
		return -2
	}

	base := uintptr(unsafe.Pointer(&inputBuf[0]))
	p := uintptr(uint32(ptr))
	if p < base || p+uintptr(length) > base+uintptr(maxInputBytes) {
		return -3
	}

	payload := unsafe.Slice((*byte)(unsafe.Pointer(p)), int(length))
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return -2
	}

	tx := engine.NewTransaction()
	defer tx.Close()

	version := req.HTTPVersion
	if version == "" {
		version = "HTTP/1.1"
	}
	uri := req.URI
	if uri == "" {
		uri = "/"
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}

	tx.ProcessURI(uri, method, version)
	for _, h := range decodeHeaders(req.Headers) {
		tx.AddRequestHeader(h[0], h[1])
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return 1
	}

	if req.Body != nil && *req.Body != "" {
		if _, _, err := tx.WriteRequestBody([]byte(*req.Body)); err != nil {
			return -4
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		return -4
	} else if it != nil {
		return 1
	}

	if tx.IsInterrupted() {
		return 1
	}
	return 0
}

//go:wasmexport free
func wafFree(ptr int32, length int32) {
	// The input buffer is static and owned by the module, so there is nothing
	// to reclaim. Kept in the ABI for host symmetry and future allocators.
}

func main() {}
