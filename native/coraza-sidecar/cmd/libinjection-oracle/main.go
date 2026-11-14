// Command libinjection-oracle produces the pinned parity oracle for the native
// Rust detectors and measures libinjection's own cost.
//
// It exists because Coraza v3.3.3 implements `@detectSQLi` as
// `libinjection.IsSQLi` and `@detectXSS` as `libinjection.IsXSS`: the verdicts
// this program records are, by definition, Coraza's operator verdicts. The
// generated JSON is committed so the Rust test suite can replay it without a
// Go toolchain.
//
// Run from native/coraza-sidecar:
//
//	go run -mod=vendor ./cmd/libinjection-oracle \
//	    -corpus ../../tests/corpus/crs/corpus.json \
//	    -out ../../tests/corpus/native-detect/oracle.json
//	go run -mod=vendor ./cmd/libinjection-oracle -bench
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/corazawaf/libinjection-go"
)

type corpusCase struct {
	Request struct {
		Method  string            `json:"method"`
		URI     string            `json:"uri"`
		Headers map[string]string `json:"headers"`
		Body    *string           `json:"body"`
	} `json:"request"`
}

type corpusFile struct {
	Cases []corpusCase `json:"cases"`
}

// oracleCase is one (value, verdict) pair. Field names are short to keep the
// committed file small: s=value, q=SQLi, x=XSS, k=kind.
type oracleCase struct {
	S string `json:"s"`
	Q bool   `json:"q"`
	X bool   `json:"x"`
	K string `json:"k"`
}

const maxValueBytes = 8192

var sqliSeeds = []string{
	"1' OR '1'='1",
	"-1' and 1=1 union/* foo */select load_file('/etc/passwd')--",
	"1 UNION SELECT username, password FROM users",
	"admin'--",
	"1;DROP TABLE users",
	"' or 1=1#",
	"1) OR 1=1--",
	"0xdeadbeef UNION ALL SELECT NULL,NULL",
	"1 AND (SELECT COUNT(*) FROM users) > 0",
	"'; WAITFOR DELAY '0:0:5'--",
	"1' AND SLEEP(5) AND '1'='1",
	"1 ORDER BY 1,2,3--",
	"\" OR \"\"=\"",
	"1/**/OR/**/1=1",
	"1' INTO OUTFILE '/tmp/x'--",
	"' UNION SELECT @@version,1,2--",
	"1' GROUP BY 1 HAVING 1=1--",
	"1' OR EXISTS(SELECT * FROM users)--",
	"1' OR 'a'='a",
	"' OR 1 --",
	"1 OR TRUE",
	"1'||'1",
	"1' + (SELECT 1) + '",
	"0x31 OR 0x31=0x31",
	"1' AND BENCHMARK(1000000,MD5(1))--",
	"1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)--",
	"' UNION ALL SELECT NULL,NULL,NULL--",
	"1' ORDER BY 100--",
	"1' LIMIT 1 OFFSET 1--",
	"1' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,VERSION())),1)--",
	"1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
	"1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
	"1' AND JSON_KEYS((SELECT CONVERT((SELECT version()) USING utf8)))--",
	"1' AND 1=CONVERT(int,(SELECT @@version))--",
	"1' AND 1=CAST((SELECT version()) AS int)--",
	"1' AND ASCII(SUBSTRING((SELECT version()),1,1))>0--",
	"1' RLIKE (SELECT 1)--",
	"1' AND '1' LIKE '1",
	"1' OR NOT 1=1--",
	"1' AND MAKE_SET(1)|1--",
	"1' AND (SELECT 1) IN (1)--",
	"1' AND 1 BETWEEN 1 AND 2--",
	"1' AND 1 IS NOT NULL--",
	"1' AND CASE WHEN 1=1 THEN 1 ELSE 0 END--",
	"1' AND IF(1=1,SLEEP(1),0)--",
	"1' AND ELT(1=1,1)--",
	"1' AND (SELECT * FROM users LIMIT 1)--",
	"1' COLLATE latin1_general_cs--",
	"1' AND @@version_comment LIKE '%MySQL%'--",
	"1' AND LOAD_FILE('/etc/passwd')--",
}

var xssSeeds = []string{
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"<svg/onload=alert(1)>",
	"<iframe src=javascript:alert(1)>",
	"<a href=\"javascript:alert(1)\">x</a>",
	"<body onload=alert(1)>",
	"<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
	"<!--[if IE]><script>x</script><![endif]-->",
	"<div style=\"background:url(javascript:alert(1))\">",
	"<object data=\"data:text/html;base64,PHNjcmlwdD4=\">",
	"<scr<script>ipt>alert(1)</script>",
	"\\\"><script>alert(1)</script>",
	"<img src=1 onerror=alert(1)//",
	"<x onmouseover=alert(1)>",
	"<input autofocus onfocus=alert(1)>",
	"<details open ontoggle=alert(1)>",
	"<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
	"<math><mtext></mtext><script>alert(1)</script></math>",
	"<template><script>alert(1)</script></template>",
	"<form action=javascript:alert(1)><input type=submit>",
	"<base href=javascript:alert(1)//>",
	"<link rel=import href=data:text/html,x>",
	"<isindex action=javascript:alert(1) type=image>",
	"<video poster=javascript:alert(1)>",
	"<table background=javascript:alert(1)>",
	"<xml id=x><x:script>alert(1)</x:script></xml>",
	"<style>@import 'javascript:alert(1)';</style>",
	"<title><script>alert(1)</script></title>",
	"<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
	"<!--`--><script>alert(1)</script>",
	"<!--<img src=x onerror=alert(1)>-->",
	"<?import namespace=\"x\" implementation=\"javascript:alert(1)\"?>",
	"<![CDATA[<script>alert(1)</script>]]>",
	"<html:script>alert(1)</html:script>",
	"<svg><handler xmlns:ev=\"http://www.w3.org/2001/xml-events\" ev:event=\"load\">alert(1)</handler></svg>",
}

var benignSeeds = []string{
	"hello world",
	"name=alice&city=paris",
	"The quick brown fox jumps over the lazy dog",
	"select a coffee",
	"1 and 2",
	"user@example.com",
	"a < b and b > c",
	"https://example.com/path?q=1",
	"{\"json\":true,\"msg\":\"ok\"}",
	"2026-11-02T12:00:00Z",
	"drop by the store",
	"update your profile",
	"it's a beautiful day",
	"don't stop",
	"50% off",
	"<3",
	"x > 1",
	"C++ is fun",
	"email: test@test.com; phone: 555",
	"I have 2 apples and 3 oranges",
	"path/to/file.txt",
	"ORDER BY date",
	"union square",
	"select * from menu",
	"the script is ready",
	"javascript is a language",
	"style guide",
	"<b>bold</b>",
	"<p>paragraph</p>",
	"</div>",
	"a href link",
	"onerror handling",
	"table of contents",
	"insert coin",
	"delete this line",
	"where are you",
	"having fun",
	"group by category",
	"limit 10 results",
	"offset 20",
	"executive summary",
	"sleep well",
	"benchmark results",
	"load file",
	"version 1.2.3",
	"cast iron",
	"convert 10 usd",
	"concat strings",
	"null value",
	"true story",
	"1=1 in maths",
	"a=b",
	"2 + 2 = 4",
	"price: $1,000.00",
	"user_id=42",
	"SELECT",
	"'quoted'",
	"\"double quoted\"",
	"back`tick",
	"semi;colon",
	"comment /* here */",
	"dash-dash",
	"hash #tag",
	"percent 100%",
	"at @sign",
	"amp & more",
	"pipe | or",
	"tilde ~ home",
	"caret ^ hat",
	"bracket [x]",
	"brace {y}",
	"colon : value",
}

// urlEncode encodes bytes that matter to the detectors, leaving the rest.
func urlEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"', '<', '>', '(', ')', ' ', '/', '\\', '#', ';', '=', '-':
			fmt.Fprintf(&b, "%%%02X", s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// htmlEncode encodes the characters that make markup, leaving text intact.
func htmlEncode(s string) string {
	r := strings.NewReplacer("<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#x27;")
	return r.Replace(s)
}

func commentize(s string) string {
	return strings.NewReplacer(" ", "/**/", "\t", "/**/").Replace(s)
}

func alternateCase(s string) string {
	out := []byte(s)
	upper := true
	for i := range out {
		c := out[i]
		if c >= 'a' && c <= 'z' && upper {
			out[i] = c - 32
		} else if c >= 'A' && c <= 'Z' && !upper {
			out[i] = c + 32
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			upper = !upper
		}
	}
	return string(out)
}

func unicodeFullwidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '!' && r <= '~':
			b.WriteRune(r - '!' + 0xFF01)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func variants(seed string) []string {
	return []string{
		seed,
		strings.ToUpper(seed),
		strings.ToLower(seed),
		alternateCase(seed),
		" " + seed,
		seed + " ",
		"\t\n" + seed + "\r\n",
		strings.ReplaceAll(seed, " ", "\t"),
		commentize(seed),
		urlEncode(seed),
		htmlEncode(seed),
		unicodeFullwidth(seed),
		strings.ReplaceAll(seed, "e", "\u200be"),
		strings.ReplaceAll(seed, "'", "''"),
		strings.ReplaceAll(seed, "'", "\\'"),
		strings.ReplaceAll(seed, " ", "  "),
		strings.ReplaceAll(seed, " ", "\x00"),
		"x" + seed + "y",
		"{\"v\":\"" + strings.ReplaceAll(seed, "\"", "\\\"") + "\"}",
		"v=" + strings.ReplaceAll(seed, "&", "%26"),
		seed[:len(seed)/2],
	}
}

// mutants performs deterministic ASCII byte edits so the corpus exercises
// tokenizer edge cases (unbalanced quotes, comment starts, operators).
func mutants(rng *rand.Rand, seed string, count int) []string {
	alphabet := []byte(" \t\n'\"`()[]{}<>;:,.\\/*-+=%#@!~&|^$_0123456789abcXYZ")
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		b := []byte(seed)
		edits := 1 + rng.Intn(3)
		for e := 0; e < edits; e++ {
			switch rng.Intn(4) {
			case 0: // replace
				if len(b) > 0 {
					b[rng.Intn(len(b))] = alphabet[rng.Intn(len(alphabet))]
				}
			case 1: // insert
				pos := rng.Intn(len(b) + 1)
				c := alphabet[rng.Intn(len(alphabet))]
				b = append(b[:pos], append([]byte{c}, b[pos:]...)...)
			case 2: // delete
				if len(b) > 1 {
					pos := rng.Intn(len(b))
					b = append(b[:pos], b[pos+1:]...)
				}
			case 3: // duplicate a run
				if len(b) > 1 {
					pos := rng.Intn(len(b))
					n := 1 + rng.Intn(len(b)-pos)
					b = append(b[:pos+n], append(append([]byte{}, b[pos:pos+n]...), b[pos+n:]...)...)
				}
			}
		}
		out = append(out, string(b))
	}
	return out
}

func addValue(seen map[string]struct{}, out *[]oracleCase, value, kind string) {
	if value == "" || len(value) > maxValueBytes {
		return
	}
	if _, ok := seen[value]; ok {
		return
	}
	seen[value] = struct{}{}
	q, _ := libinjection.IsSQLi(value)
	*out = append(*out, oracleCase{S: value, Q: q, X: libinjection.IsXSS(value), K: kind})
}

func generate(corpusPath string) ([]oracleCase, error) {
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		return nil, err
	}
	var corpus corpusFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	out := make([]oracleCase, 0, 16384)

	for _, c := range corpus.Cases {
		addValue(seen, &out, c.Request.Method, "crs")
		addValue(seen, &out, c.Request.URI, "crs")
		for name, value := range c.Request.Headers {
			addValue(seen, &out, name, "crs")
			addValue(seen, &out, value, "crs")
		}
		if c.Request.Body != nil {
			addValue(seen, &out, *c.Request.Body, "crs")
		}
	}

	seeds := append(append(append([]string{}, sqliSeeds...), xssSeeds...), benignSeeds...)
	rng := rand.New(rand.NewSource(20261102))
	for _, seed := range seeds {
		for _, v := range variants(seed) {
			addValue(seen, &out, v, "variant")
		}
		for _, m := range mutants(rng, seed, 40) {
			addValue(seen, &out, m, "mutant")
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].S < out[j].S })
	return out, nil
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func bench() {
	benign := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 512)
	attack := strings.Repeat("1' OR '1'='1 <script>alert(1)</script> ", 512)
	fmt.Printf("%-8s %-14s %12s %12s %10s\n", "body", "input", "p50", "p99", "MB/s")
	for _, size := range []int{1024, 4096, 8192} {
		for name, src := range map[string]string{"benign": benign, "attack": attack} {
			body := src[:size]
			const reps = 2000
			samples := make([]time.Duration, 0, reps)
			for i := 0; i < reps; i++ {
				start := time.Now()
				libinjection.IsSQLi(body)
				libinjection.IsXSS(body)
				samples = append(samples, time.Since(start))
			}
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			p50 := percentile(samples, 0.50)
			p99 := percentile(samples, 0.99)
			mbps := float64(size) / p50.Seconds() / (1024 * 1024)
			fmt.Printf("%-8d %-14s %12s %12s %10.1f\n", size, name, p50, p99, mbps)
		}
	}
}

func main() {
	corpus := flag.String("corpus", "../../tests/corpus/crs/corpus.json", "CRS corpus JSON")
	out := flag.String("out", "../../tests/corpus/native-detect/oracle.json", "oracle output path")
	doBench := flag.Bool("bench", false, "measure libinjection cost instead of generating")
	flag.Parse()

	if *doBench {
		bench()
		return
	}

	cases, err := generate(*corpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oracle: %v\n", err)
		os.Exit(1)
	}
	encoded, err := json.Marshal(cases)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oracle: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "oracle: %v\n", err)
		os.Exit(1)
	}

	var sqli, xss int
	for _, c := range cases {
		if c.Q {
			sqli++
		}
		if c.X {
			xss++
		}
	}
	fmt.Fprintf(os.Stderr, "oracle: %d values (%d sqli, %d xss) -> %s\n", len(cases), sqli, xss, *out)
}
