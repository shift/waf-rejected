package main

import (
	"fmt"
	"strings"
	"testing"
)

// attackCorpus is the request-side detection corpus used to prove that
// enabling CRS early blocking does not change a single decision. It mirrors the
// payloads in tests/common/mod.rs and adds the categories the native e2e suite
// exercises (SQLi, XSS, LFI, RCE, RFI/SSRF, SSTI, LDAP).
var attackCorpus = []struct {
	name        string
	payload     string
	expectBlock bool
}{
	{"sqli-classic", "' OR '1'='1' --", true},
	{"sqli-union", "' UNION SELECT username, password FROM users --", true},
	{"sqli-time", "'; WAITFOR DELAY '00:00:05' --", true},
	{"xss-script", "<script>alert('XSS')</script>", true},
	{"xss-js-uri", "javascript:alert('XSS')", true},
	{"xss-img", "<img src=x onerror=alert('XSS')>", true},
	{"rce-cat", "; cat /etc/passwd", true},
	{"rce-powershell", "; Get-Process", true},
	{"rce-shell", "cmd=;cat+/etc/passwd", true},
	{"lfi-traversal", "../../../../etc/passwd", true},
	{"lfi-windows", "..\\..\\..\\windows\\system32\\config\\sam", true},
	{"rfi-url", "http://evil.com/shell.php", false},
	{"xxe", `<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>`, true},
	{"ssti", "{{7*7}}", false},
	{"ldap", "*)(&)", false},
}

var benignCorpus = []struct {
	name    string
	payload string
}{
	{"json", `{"user_id": 12345, "action": "get_profile"}`},
	{"special-chars", "search for C++ programming & .NET development"},
	{"escaped-quotes", `{"message": "He said \"Hello\" to me"}`},
	{"url-params", "/api/users?page=1&limit=50&sort=name"},
}

// TestEarlyBlockingPreservesDecisions runs every corpus payload through two
// engines (early blocking off/on) in both the query string and the body and
// requires identical decisions. This is the regression guard for the sidecar
// performance change: the optimisation may only skip work for requests that
// are already blocked.
func TestEarlyBlockingPreservesDecisions(t *testing.T) {
	off := testServerWith(t, false)
	on := testServerWith(t, true)

	check := func(t *testing.T, name string, req map[string]any, want string) {
		t.Helper()
		gotOff := decision(t, off, req)
		gotOn := decision(t, on, req)
		if gotOff != gotOn {
			t.Fatalf("%s: decision changed with early blocking: off=%q on=%q", name, gotOff, gotOn)
		}
		if gotOn != want {
			t.Fatalf("%s: decision = %q, want %q", name, gotOn, want)
		}
	}

	for _, tc := range attackCorpus {
		// CRS PL1 does not block a few of these payload shapes (RFI, SSTI,
		// LDAP); for those the guard is decision parity, not a block.
		want := "allow"
		if tc.expectBlock {
			want = "block"
		}
		t.Run("query/"+tc.name, func(t *testing.T) {
			check(t, tc.name, base("/search?q="+tc.payload), want)
		})
		t.Run("body/"+tc.name, func(t *testing.T) {
			check(t, tc.name, form("POST", "/submit", "data="+tc.payload), want)
		})
	}
	for _, tc := range benignCorpus {
		t.Run("benign/"+tc.name, func(t *testing.T) {
			check(t, tc.name, form("POST", "/submit", "data="+tc.payload), "allow")
		})
	}
}

// TestEarlyBlockingStopsBeforeBodyScan documents the mechanism: a request whose
// phase-1 score is already over the threshold is interrupted by rule 949111
// (phase 1) when early blocking is enabled, instead of 949110 (phase 2) after
// the body has been scanned.
func TestEarlyBlockingStopsBeforeBodyScan(t *testing.T) {
	scanner := func() map[string]any {
		req := form("POST", "/submit", "data="+string(benchFormBody(8<<10)))
		req["headers"] = [][2]string{
			{"host", "example.test"},
			{"content-type", "application/x-www-form-urlencoded"},
			{"user-agent", "sqlmap/1.7.2#stable (https://sqlmap.org)"},
		}
		return req
	}

	for _, tc := range []struct {
		name string
		srv  *server
		rule string
	}{
		{"disabled", testServerWith(t, false), "949110"},
		{"enabled", testServerWith(t, true), "949111"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.srv.evaluate(payload(t, scanner()))
			if resp.Decision != "block" {
				t.Fatalf("decision = %q, want block", resp.Decision)
			}
			if want := fmt.Sprintf("rule %s", tc.rule); !strings.Contains(resp.Reason, want) {
				t.Fatalf("reason = %q, want it to contain %q", resp.Reason, want)
			}
		})
	}
}
