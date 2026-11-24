package scopelint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hostryhq/go-auth/scopelint"
)

var tables = scopelint.Tables{
	"orders":   scopelint.OutletScoped,
	"devices":  scopelint.OutletScoped,
	"brands":   scopelint.TenantWide,
	"settings": scopelint.OutletScoped,
}

// ADR-0003 A1.4 item 5: a statement on an outlet-scoped table needs a bound
// outlet_id predicate; tenant-wide tables need none.
func TestCheckSQL(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		bad  bool
	}{
		{"list with equality", `SELECT id FROM orders WHERE tenant_id = $1 AND outlet_id = $2`, false},
		{"list with ANY of the scope", `SELECT id FROM orders WHERE tenant_id = $1 AND outlet_id = ANY($2)`, false},
		{"list with IN", `select id from orders where tenant_id=$1 and outlet_id in ($2, $3)`, false},
		{"alias qualified", `SELECT o.id FROM orders o WHERE o.tenant_id = $1 AND o.outlet_id = ANY($2::uuid[])`, false},
		{"named parameter", `SELECT id FROM orders WHERE outlet_id = @outlet`, false},
		{"tenant filter only (the T-I2 bug)", `SELECT id FROM orders WHERE tenant_id = $1`, true},
		{"no where at all", `SELECT id FROM orders`, true},
		{"literal outlet, not bound", `SELECT id FROM orders WHERE outlet_id = 'abc'`, true},
		{"outlet predicate only inside a string", `SELECT id FROM orders WHERE note = 'outlet_id = $1'`, true},
		{"outlet_id selected but not filtered", `SELECT outlet_id, id FROM orders WHERE tenant_id = $1`, true},
		{"tenant-wide table", `SELECT id FROM brands WHERE tenant_id = $1`, false},
		{"unknown table is not this lint's business", `SELECT 1 FROM pg_catalog`, false},
		{"update with predicate", `UPDATE orders SET status = $1 WHERE tenant_id = $2 AND outlet_id = $3 AND id = $4`, false},
		{"update setting outlet_id is not a predicate", `UPDATE orders SET outlet_id = $1 WHERE id = $2`, true},
		{"delete without predicate", `DELETE FROM devices WHERE tenant_id = $1 AND id = $2`, true},
		{"delete with predicate", `DELETE FROM devices WHERE tenant_id = $1 AND outlet_id = $2 AND id = $3`, false},
		{"insert with outlet column", `INSERT INTO orders (tenant_id, outlet_id, id) VALUES ($1, $2, $3)`, false},
		{"insert without outlet column", `INSERT INTO orders (tenant_id, id) VALUES ($1, $2)`, true},
		{"insert into tenant-wide", `INSERT INTO brands (tenant_id, id) VALUES ($1, $2)`, false},
		{"join: one predicate for two outlet tables", `SELECT * FROM orders o JOIN devices d ON d.id = o.device_id WHERE o.outlet_id = $1`, true},
		{"join: a predicate for each", `SELECT * FROM orders o JOIN devices d ON d.id = o.device_id AND d.outlet_id = $2 WHERE o.outlet_id = $1`, false},
		{"join to a tenant-wide table", `SELECT * FROM orders o JOIN brands b ON b.id = o.brand_id WHERE o.outlet_id = $1`, false},
		{"comma join", `SELECT * FROM orders o, devices d WHERE o.outlet_id = $1`, true},
		{"schema qualified", `SELECT id FROM public.orders WHERE tenant_id = $1`, true},
		{"insert select reads outlet-scoped rows", `INSERT INTO brands (tenant_id, id) SELECT tenant_id, id FROM orders WHERE tenant_id = $1`, true},
		{"count over a scoped table", `SELECT count(*) FROM orders WHERE tenant_id = $1`, true},
		{"trailing semicolon and comment", "SELECT id FROM orders -- list\nWHERE outlet_id = $1;", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scopelint.CheckSQL(c.sql, tables)
			if (len(got) > 0) != c.bad {
				t.Fatalf("findings %v, want bad=%v", got, c.bad)
			}
		})
	}
}

const goSource = `package repo

const listOK = "SELECT id FROM orders WHERE tenant_id = $1 AND outlet_id = ANY($2)"

const listLeaky = "SELECT id FROM orders WHERE tenant_id = $1"

//scopelint:internal sync apply runs per tenant with no outlet filter
const applyInternal = "UPDATE orders SET status = $1 WHERE tenant_id = $2 AND id = $3"

const trailing = "DELETE FROM devices WHERE id = $1" //scopelint:internal per-tenant reaper

//scopelint:internal
const noReason = "SELECT id FROM orders"

var notSQL = "update the thing"
`

func TestCheckGoSourceAndMarkers(t *testing.T) {
	got, err := scopelint.CheckGoSource("repo.go", []byte(goSource), tables)
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range got {
		lines = append(lines, f.Line)
	}
	// listLeaky (line 5) and the marker with no reason (line 12); the marked
	// statements and the English sentence are not findings.
	if len(got) != 2 || got[0].Line != 5 || got[1].Line != 12 || !strings.Contains(got[1].Message, "reason") {
		t.Fatalf("findings: %v", got)
	}
}

func TestCheckDirSkipsMigrationsAndTests(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("repository/repo.go", goSource)
	write("repository/repo_test.go", `package repo
const q = "SELECT id FROM orders"`)
	write("repository/queries/list.sql", "-- list orders\nSELECT id FROM orders WHERE tenant_id = $1;\n\n-- scopelint:internal reaper\nDELETE FROM devices WHERE id = $1;\n")
	write("repository/migrations/001.sql", "SELECT id FROM orders;")
	got, err := scopelint.CheckDir(dir, tables)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range got {
		files = append(files, filepath.Base(f.File))
	}
	if len(got) != 3 || files[0] != "list.sql" || files[1] != "repo.go" || files[2] != "repo.go" {
		t.Fatalf("findings: %v", got)
	}
}

func TestLoadTablesRejectsUnknownKind(t *testing.T) {
	if _, err := scopelint.LoadTables([]byte(`{"orders":"mostly_scoped"}`)); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := scopelint.LoadTables([]byte(`{"orders":"outlet_scoped"}`)); err != nil {
		t.Fatal(err)
	}
}
