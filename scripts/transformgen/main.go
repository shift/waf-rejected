// Command transformgen produces the ground-truth fixtures used by
// `src/waf/transforms.rs` differential tests.
//
// It is not part of the Rust build. `scripts/gen-transform-fixture.sh` copies
// the vendored Coraza transform sources (wasm/coraza_reactor/vendor) next to
// this file, renames their package to `main`, and runs it. Calling the
// unexported Coraza functions directly guarantees that the fixture is produced
// by the exact code the WASI reactor executes, not by a re-implementation.
//
// Outputs:
//   - transform_parity.json: generated inputs and the Coraza output for every
//     supported transform, hex encoded.
//   - entities.rs: the golang.org/x/net/html named-entity table.
//   - case_tables.rs: Go's simple (per-rune) lower/upper case tables.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"unicode"
)

type transformFunc func(string) (string, bool, error)

var transforms = []struct {
	name string
	fn   transformFunc
}{
	{"lowercase", lowerCase},
	{"uppercase", upperCase},
	{"urlDecode", urlDecode},
	{"urlDecodeUni", urlDecodeUni},
	{"removeNulls", removeNulls},
	{"replaceNulls", replaceNulls},
	{"compressWhitespace", compressWhitespace},
	{"removeWhitespace", removeWhitespace},
	{"trim", trim},
	{"trimLeft", trimLeft},
	{"trimRight", trimRight},
	{"normalizePath", normalisePath},
	{"normalizePathWin", normalisePathWin},
	{"escapeSeqDecode", escapeSeqDecode},
	{"replaceComments", replaceComments},
	{"jsDecode", jsDecode},
	{"cssDecode", cssDecode},
	{"htmlEntityDecode", htmlEntityDecode},
	{"cmdLine", cmdLine},
	{"base64Decode", base64decode},
}

type fixture struct {
	Engine     string     `json:"engine"`
	Transforms []string   `json:"transforms"`
	Inputs     []string   `json:"inputs"`
	Outputs    [][]string `json:"outputs"`
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: transformgen <fixture.json> <entities.rs> <case_tables.rs>")
		os.Exit(2)
	}
	if err := writeFixture(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "fixture: %v\n", err)
		os.Exit(1)
	}
	if err := writeEntities(os.Args[2], "html/entity.go"); err != nil {
		fmt.Fprintf(os.Stderr, "entities: %v\n", err)
		os.Exit(1)
	}
	if err := writeCaseTables(os.Args[3]); err != nil {
		fmt.Fprintf(os.Stderr, "case tables: %v\n", err)
		os.Exit(1)
	}
}

func writeFixture(path string) error {
	inputs := generatedInputs()
	out := fixture{
		Engine:     "corazawaf/coraza v3.3.3 (vendored) + golang.org/x/net/html",
		Transforms: make([]string, len(transforms)),
		Inputs:     make([]string, len(inputs)),
		Outputs:    make([][]string, len(inputs)),
	}
	for i, t := range transforms {
		out.Transforms[i] = t.name
	}
	for i, in := range inputs {
		out.Inputs[i] = hex.EncodeToString([]byte(in))
		row := make([]string, len(transforms))
		for j, t := range transforms {
			res, _, err := t.fn(in)
			if err != nil {
				return fmt.Errorf("%s on %q: %w", t.name, in, err)
			}
			row[j] = hex.EncodeToString([]byte(res))
		}
		out.Outputs[i] = row
	}
	data, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func generatedInputs() []string {
	fixed := []string{
		"", "a", "A", "abc", "ABC", "AbC", "hello world", "  hello\tworld\n",
		"\t\n\v\f\r ", "\x85\xa0", "a\x00b", "\x00\x00",
		"%41", "%4", "%", "%%", "%zz", "%ZZ", "%u0041", "%u005c", "%uZZZZ",
		"%u12", "%U0041", "%uFF41", "%uff21", "%25", "%2541", "%252541",
		"%25zz", "%2525", "a+b", "+", "a%2Bb", "a%2b%2b", "q=1%20UNION%20SELECT",
		"%3Cscript%3E", "%c0%80", "%e0%a0", "%f0%9f%92%a9", "%41%42%43",
		"%4142", "%u0041%u0042", "a%u004", "a%u004G",
		"café", "İstanbul", "Σσς", "ẞß", "日本語", "💩", "a\u0301",
		"x\xffy", "\xff\xfe", "\xc0\x80", "\xe0\xa0", "\xf0\x9f", "\xed\xa0\x80",
		"&lt;", "&gt;", "&amp;", "&quot;", "&apos;", "&nbsp;", "&#60;",
		"&#x3c;", "&#X3C;", "&#0;", "&#x0;", "&#128;", "&#x80;", "&#x9f;",
		"&#xD800;", "&#xDFFF;", "&#x110000;", "&#x10FFFF;",
		"&#12345678901234567890;", "&lt", "&gt", "&amp", "&amp=", "&ampx",
		"&notit;", "&notin;", "&NotEqualTilde;", "&sol;", "&hyphen;", "&", "&&",
		"&#;", "&#x;", "&#xg;", "a&b", "<script>alert('x')</script>",
		"a/b/../c", "//a//b/./c/", "/../..", "a/../../b", "\\a\\b\\",
		"a\\\\b", "C:\\Windows\\..\\x", ".", "..", "/", "///", "a/b/", "./a",
		"../a", "cat /etc/passwd", "CAT  /etc/passwd", "cat (x)", "a;b,c",
		"a\"b'c\\d^e", "a , b", "ls -la /tmp", "a\\x41b", "a\\101b", "a\\0b",
		"a\\q", "a\\", "\\", "\\n\\t\\r", "\\u0041", "\\uFF41", "\\u12",
		"\\uZZZZ", "\\x41", "\\x4", "\\xZZ", "\\101", "\\777", "\\400",
		"a\\/b", "a\\*b", "a/*b*/c", "/*x*/", "/* unterminated", "a/*b*/c/*d*/e",
		"a*/b", "a/*/b", "SGVsbG8=", "SGVsbG8", "SGVsbG8h", "SGV sbG8=",
		"SGVs\nbG8=", "SGVsbG8===", "====", "AA==", "AAA=", "AAAA",
		"aGVsbG8gd29ybGQ=", "!!!!", "SGVsbG8*", "SGVsbG8.", "\xff", "é",
		"e\u0301", "\\u0000", "\\uD800", "\\uDC00", "\\u00e9", "\\u20ac",
		"a\\u0041b\\x42c\\103d", "%u0000", "%uD800", "%uFF5E", "%uFF01",
	}

	// Deterministic pseudo-random byte strings. The alphabet is weighted
	// towards bytes that every transform treats specially.
	alphabet := []byte{
		0x00, '%', '+', '&', '#', ';', '\\', '/', '.', 'u', 'U', 'x', 'X',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c',
		'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F', 'g', 'z', 'Z', '<',
		'>', '"', '\'', '^', ',', ' ', '\t', '\n', '\r', '\v', '\f', '=',
		'(', ')', '*', ':', '?', '_', '-', '|', '{', '}', '~', 0x7f,
		0x80, 0x85, 0xa0, 0xc0, 0xe0, 0xf0, 0xff,
	}

	var x uint64 = 0x9e3779b97f4a7c15
	next := func() uint64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return x
	}
	random := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		n := int(next() % 49)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[next()%uint64(len(alphabet))]
		}
		random = append(random, string(b))
	}
	return append(fixed, random...)
}

// writeEntities extracts the named-entity tables from the vendored
// golang.org/x/net/html/entity.go source.
func writeEntities(path, source string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, source, nil, 0)
	if err != nil {
		return err
	}
	values := map[string][2]rune{}
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.VAR {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Values == nil {
				continue
			}
			name := vs.Names[0].Name
			if name != "entity" && name != "entity2" {
				continue
			}
			lit, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, err := strconv.Unquote(kv.Key.(*ast.BasicLit).Value)
				if err != nil {
					continue
				}
				switch value := kv.Value.(type) {
				case *ast.BasicLit:
					r := unquoteRune(value)
					values[key] = [2]rune{r, 0}
				case *ast.CompositeLit:
					var pair [2]rune
					for i, item := range value.Elts {
						if i < 2 {
							pair[i] = unquoteRune(item.(*ast.BasicLit))
						}
					}
					values[key] = pair
				}
			}
		}
		return true
	})
	if len(values) == 0 {
		return fmt.Errorf("no entities found in %s", source)
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	var b []byte
	b = append(b, "// @generated by scripts/gen-transform-fixture.sh. Do not edit.\n"...)
	b = append(b, "//\n// Named HTML5 entities from golang.org/x/net/html/entity.go, the table\n// Coraza's htmlEntityDecode uses.\n\n"...)
	b = append(b, "pub(super) static ENTITIES: &[(&str, [u32; 2])] = &[\n"...)
	for _, name := range names {
		v := values[name]
		b = append(b, fmt.Sprintf("    (%q, [0x%04X, 0x%04X]),\n", name, v[0], v[1])...)
	}
	b = append(b, "];\n"...)
	return os.WriteFile(path, b, 0o644)
}

func unquoteRune(lit *ast.BasicLit) rune {
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return unicode.ReplacementChar
	}
	for _, r := range s {
		return r
	}
	return unicode.ReplacementChar
}

// writeCaseTables emits Go's simple (context-free) case mappings, which is
// what strings.ToLower/ToUpper apply. Rust's char::to_lowercase uses full
// mappings (e.g. U+0130 -> "i\u{307}"), so the tables are generated from Go
// to keep byte-for-byte parity.
func writeCaseTables(path string) error {
	var lower, upper [][2]rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		if l := unicode.ToLower(r); l != r {
			lower = append(lower, [2]rune{r, l})
		}
		if u := unicode.ToUpper(r); u != r {
			upper = append(upper, [2]rune{r, u})
		}
	}
	var b []byte
	b = append(b, "// @generated by scripts/gen-transform-fixture.sh. Do not edit.\n"...)
	b = append(b, "//\n// Go's simple (context-free) case mappings, as applied by\n// strings.ToLower/strings.ToUpper in the vendored Coraza build.\n\n"...)
	writeTable := func(name string, table [][2]rune) {
		b = append(b, fmt.Sprintf("pub(super) static %s: &[(u32, u32)] = &[\n", name)...)
		for _, pair := range table {
			b = append(b, fmt.Sprintf("    (0x%04X, 0x%04X),\n", pair[0], pair[1])...)
		}
		b = append(b, "];\n\n"...)
	}
	writeTable("LOWER", lower)
	writeTable("UPPER", upper)
	return os.WriteFile(path, b, 0o644)
}
