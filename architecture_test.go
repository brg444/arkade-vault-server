package pack_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/brg444/arkade-runtime"

func TestInternalImportBoundaries(t *testing.T) {
	goBinary := filepath.Join(goruntime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBinary, "list", "-json", "./...")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	allowed := map[string]map[string]bool{
		modulePath + "/internal/apperr":                 {},
		modulePath + "/internal/contractpack":           {},
		modulePath + "/internal/deployment":             {},
		modulePath + "/internal/ports":                  {},
		modulePath + "/internal/program":                {},
		modulePath + "/internal/runtime":                {},
		modulePath + "/internal/webauthn":               {},
		modulePath + "/internal/vault":                  {},
		modulePath + "/internal/vault/savings":          {modulePath + "/internal/program": true},
		modulePath + "/internal/vault/light":            {modulePath + "/internal/program": true},
		modulePath + "/internal/policy":                 {modulePath + "/internal/program": true},
		modulePath + "/internal/iface/http":             {modulePath + "/internal/application": true},
		modulePath + "/internal/profile/vaultedlightv1": {modulePath + "/internal/runtime": true, modulePath + "/internal/vault/light": true},
		modulePath + "/internal/profile/arkadevaultv1": {
			modulePath + "/internal/policy":  true,
			modulePath + "/internal/program": true,
			modulePath + "/internal/runtime": true,
		},
	}
	compositionRoots := map[string]bool{
		modulePath + "/cmd/authorizer":       true,
		modulePath + "/internal/application": true,
		modulePath + "/internal/authorizer":  true,
	}
	nonProductionPackages := map[string]bool{
		modulePath:              true,
		modulePath + "/fixture": true,
	}

	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	seen := make(map[string]bool, len(allowed))
	for decoder.More() {
		var pkg struct {
			ImportPath string
			Imports    []string
		}
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		if !strings.HasPrefix(pkg.ImportPath, modulePath) {
			continue
		}
		want, tracked := allowed[pkg.ImportPath]
		if !tracked && !compositionRoots[pkg.ImportPath] && !nonProductionPackages[pkg.ImportPath] {
			t.Errorf("production package is not classified: %s", pkg.ImportPath)
			continue
		}
		seen[pkg.ImportPath] = true
		var unexpected []string
		for _, imported := range pkg.Imports {
			if imported == modulePath+"/fixture" && !nonProductionPackages[pkg.ImportPath] {
				unexpected = append(unexpected, imported)
				continue
			}
			if tracked && strings.HasPrefix(imported, modulePath+"/internal/") && !want[imported] {
				unexpected = append(unexpected, imported)
			}
		}
		if len(unexpected) > 0 {
			sort.Strings(unexpected)
			t.Errorf("%s crossed its import boundary: %v", pkg.ImportPath, unexpected)
		}
	}
	for pkg := range allowed {
		if !seen[pkg] {
			t.Errorf("tracked package is missing: %s", pkg)
		}
	}
}
