// Command scopelint is the CI gate for ADR-0003 A1.4 item 5. Usage:
//
//	scopelint -tables tables.json ./repository ./service
//
// tables.json maps each tenant-owned table to "outlet_scoped" or "tenant_wide".
// It exits 1 when any statement on an outlet-scoped table lacks a bound
// outlet_id predicate and is not marked //scopelint:internal <reason>.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hostryhq/go-auth/scopelint"
)

func main() {
	tablesFile := flag.String("tables", "", "JSON file mapping table to outlet_scoped or tenant_wide")
	flag.Parse()
	if *tablesFile == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: scopelint -tables tables.json dir...")
		os.Exit(2)
	}
	b, err := os.ReadFile(*tablesFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	tables, err := scopelint.LoadTables(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	bad := 0
	for _, dir := range flag.Args() {
		fs, err := scopelint.CheckDir(dir, tables)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, f := range fs {
			fmt.Println(f)
			bad++
		}
	}
	if bad > 0 {
		os.Exit(1)
	}
}
