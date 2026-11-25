// Package scopelint is the build check of ADR-0003 Amendment A1.4 item 5: every
// SQL statement that reads or changes an outlet-scoped table must carry an
// outlet_id predicate bound to a parameter, or be marked internal with a
// reason. It is a textual lint over Go string literals and .sql files, not a
// SQL parser, and is deliberately strict: when in doubt it reports.
//
// Statements are marked with a comment on the same line or the line above:
//
//	//scopelint:internal sync apply runs per tenant, no outlet filter
//
// (or "-- scopelint:internal reason" in .sql files). A marker with no reason is
// itself a finding. The marked statements are reviewed like the T5 allowlist.
//
// Known limits: a table alias is not tied to its predicate (the lint counts
// predicates against outlet-scoped table references), CTE bodies are scanned as
// part of the statement, and SQL built by concatenation is out of reach (the
// string-built-SQL lint of TC-05 covers that).
package scopelint

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind is a table's declared class (ADR-0003 A1.4 item 1).
type Kind string

// Table kinds.
const (
	OutletScoped Kind = "outlet_scoped"
	TenantWide   Kind = "tenant_wide"
)

// Tables maps table name to its declared kind.
type Tables map[string]Kind

// LoadTables reads {"orders": "outlet_scoped", ...}.
func LoadTables(b []byte) (Tables, error) {
	t := Tables{}
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	for n, k := range t {
		if k != OutletScoped && k != TenantWide {
			return nil, fmt.Errorf("scopelint: table %q has unknown kind %q", n, k)
		}
	}
	return t, nil
}

// Finding is one violation.
type Finding struct {
	File    string
	Line    int
	Message string
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Message) }

var (
	sqlStart  = regexp.MustCompile(`(?is)^\s*(select\b.*\bfrom\b|insert\s+into\b|update\s+\S+\s+set\b|delete\s+from\b|with\b.*\bselect\b)`)
	lineCmt   = regexp.MustCompile(`--[^\n]*`)
	strLit    = regexp.MustCompile(`'(?:[^']|'')*'`)
	spaces    = regexp.MustCompile(`\s+`)
	fromList  = regexp.MustCompile(`\bfrom\s+(.+?)(?:\s+(?:where|join|left|right|inner|outer|full|cross|group|order|limit|having|union|returning|for|on)\b|\)|$)`)
	joinRef   = regexp.MustCompile(`\bjoin\s+([a-z_][a-z0-9_.]*)`)
	updateRef = regexp.MustCompile(`^\s*update\s+(?:only\s+)?([a-z_][a-z0-9_.]*)`)
	insertRef = regexp.MustCompile(`^\s*insert\s+into\s+([a-z_][a-z0-9_.]*)\s*(?:\(([^)]*)\))?`)
	predicate = regexp.MustCompile(`(?:\b[a-z_][a-z0-9_]*\.)?\boutlet_id\s*(?:=\s*(?:any\s*\(\s*)?|in\s*\(\s*)(?:\$\d+|@\w+|:\w+|\?)`)
	markerRe  = regexp.MustCompile(`scopelint:internal(.*)`)
)

func normalise(sql string) string {
	s := lineCmt.ReplaceAllString(sql, " ")
	s = strLit.ReplaceAllString(s, "''")
	s = strings.ToLower(spaces.ReplaceAllString(s, " "))
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ";"))
}

func baseName(n string) string {
	if i := strings.LastIndexByte(n, '.'); i >= 0 {
		return n[i+1:]
	}
	return n
}

// refsOf returns the outlet-scoped tables a read/update/delete part refers to.
func refsOf(s string, t Tables) []string {
	var names []string
	if m := updateRef.FindStringSubmatch(s); m != nil {
		names = append(names, baseName(m[1]))
	}
	for _, m := range fromList.FindAllStringSubmatch(s, -1) {
		for _, item := range strings.Split(m[1], ",") {
			f := strings.Fields(strings.TrimSpace(item))
			if len(f) > 0 && f[0] != "(" && f[0] != "select" {
				names = append(names, baseName(strings.Trim(f[0], "(")))
			}
		}
	}
	for _, m := range joinRef.FindAllStringSubmatch(s, -1) {
		names = append(names, baseName(m[1]))
	}
	var out []string
	for _, n := range names {
		if t[n] == OutletScoped {
			out = append(out, n)
		}
	}
	return out
}

func predicatesAfterFilter(s string) int {
	i := strings.Index(s, " where ")
	j := strings.Index(s, " on ")
	if i < 0 || (j >= 0 && j < i) {
		i = j
	}
	if i < 0 {
		return 0
	}
	return len(predicate.FindAllString(s[i:], -1))
}

// CheckSQL returns a message for each violation in one statement.
func CheckSQL(sql string, t Tables) []string {
	s := normalise(sql)
	var msgs []string
	readPart := s
	if m := insertRef.FindStringSubmatch(s); m != nil {
		target := baseName(m[1])
		if t[target] == OutletScoped && !containsWord(m[2], "outlet_id") {
			msgs = append(msgs, "insert into outlet-scoped table "+target+" without an outlet_id column")
		}
		if i := strings.Index(s, " select "); i >= 0 {
			readPart = s[i+1:]
		} else {
			return msgs
		}
	}
	refs := refsOf(readPart, t)
	if len(refs) > 0 && predicatesAfterFilter(readPart) < len(refs) {
		msgs = append(msgs, "statement on outlet-scoped table(s) "+strings.Join(refs, ", ")+" has no bound outlet_id predicate for each")
	}
	return msgs
}

func containsWord(list, w string) bool {
	for _, c := range strings.Split(list, ",") {
		if strings.TrimSpace(c) == w {
			return true
		}
	}
	return false
}

// markerReason returns (found, reason) for a scopelint:internal marker in text.
func markerReason(text string) (bool, string) {
	m := markerRe.FindStringSubmatch(text)
	if m == nil {
		return false, ""
	}
	return true, strings.TrimSpace(m[1])
}

// CheckGoSource lints the SQL string literals of one Go file.
func CheckGoSource(filename string, src []byte, t Tables) ([]Finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	markers := map[int]string{} // line -> comment text
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			markers[fset.Position(c.Pos()).Line] = c.Text
		}
	}
	var out []Finding
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		sql, err := strconv.Unquote(lit.Value)
		if err != nil || !sqlStart.MatchString(sql) {
			return true
		}
		line := fset.Position(lit.Pos()).Line
		out = append(out, check(filename, line, sql, markers, t)...)
		return true
	})
	return out, nil
}

func check(file string, line int, sql string, markers map[int]string, t Tables) []Finding {
	msgs := CheckSQL(sql, t)
	if len(msgs) == 0 {
		return nil
	}
	for _, l := range []int{line, line - 1} {
		if found, reason := markerReason(markers[l]); found {
			if reason == "" {
				return []Finding{{file, l, "scopelint:internal marker needs a reason"}}
			}
			return nil
		}
	}
	out := make([]Finding, len(msgs))
	for i, m := range msgs {
		out[i] = Finding{file, line, m}
	}
	return out
}

// CheckSQLFile lints a .sql file, one statement at a time.
func CheckSQLFile(filename string, src []byte, t Tables) []Finding {
	lines := strings.Split(string(src), "\n")
	markers := map[int]string{}
	for i, l := range lines {
		if k := strings.Index(l, "--"); k >= 0 {
			markers[i+1] = l[k:]
		}
	}
	var out []Finding
	start, buf := 1, strings.Builder{}
	flush := func() {
		if strings.TrimSpace(buf.String()) != "" && sqlStart.MatchString(stripLeadingComments(buf.String())) {
			out = append(out, check(filename, start, buf.String(), markers, t)...)
		}
		buf.Reset()
	}
	for i, l := range lines {
		if buf.Len() == 0 && strings.TrimSpace(l) == "" {
			continue
		}
		if buf.Len() == 0 {
			start = i + 1
		}
		buf.WriteString(l + "\n")
		if strings.HasSuffix(strings.TrimSpace(lineCmt.ReplaceAllString(l, "")), ";") {
			flush()
		}
	}
	flush()
	return out
}

func stripLeadingComments(s string) string { return lineCmt.ReplaceAllString(s, " ") }

// CheckDir walks root and lints every non-test .go file and every .sql file
// outside a "migrations" directory. Generated and vendored trees are skipped.
func CheckDir(root string, t Tables) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", ".git", "migrations", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			found, err := CheckGoSource(path, b, t)
			if err != nil {
				return err
			}
			out = append(out, found...)
		case strings.HasSuffix(path, ".sql"):
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out = append(out, CheckSQLFile(path, b, t)...)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, err
}
