package core_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const corePrefix = "github.com/code-corhuila/multi-tour-security/internal/core"

// Go has no compiler barrier between the packages of one module, so this test is the barrier:
// the core may import only the standard library and itself (norm §5.3; constitution, Article IV).
// It reads the sources instead of running `go list`, so `go test` sees them and never serves a
// cached verdict after an import changes. Test files are checked too: a core test may not pull a
// framework either.
func TestC_CoreImportsOnlyTheStandardLibrary(t *testing.T) {
	fset := token.NewFileSet()
	parsed := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		parsed++
		for _, spec := range file.Imports {
			imported, _ := strconv.Unquote(spec.Path.Value)
			if !isAllowed(imported) {
				t.Errorf("%s imports %s, which is neither the standard library nor the core", path, imported)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed == 0 {
		t.Fatal("no source file was read: the guard would pass without checking anything")
	}
}

func TestC_ImportRuleRejectsLookalikes(t *testing.T) {
	cases := map[string]bool{
		"fmt":                          true,
		"net/http":                     true,
		corePrefix:                     true,
		corePrefix + "/port":           true,
		corePrefix + "x":               false,
		corePrefix + "-http":           false,
		"github.com/golang-jwt/jwt/v5": false,
		"C":                            false,
	}
	for imported, want := range cases {
		if got := isAllowed(imported); got != want {
			t.Errorf("isAllowed(%q) = %v, want %v", imported, got, want)
		}
	}
}
