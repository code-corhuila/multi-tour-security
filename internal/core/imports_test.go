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
// cached verdict after an import changes.
func TestC_CoreImportsOnlyTheStandardLibrary(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			imported, _ := strconv.Unquote(spec.Path.Value)
			// a standard library path has no dot in its first element
			first, _, _ := strings.Cut(imported, "/")
			if strings.Contains(first, ".") && !strings.HasPrefix(imported, corePrefix) {
				t.Errorf("%s imports %s, which is neither the standard library nor the core", path, imported)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
