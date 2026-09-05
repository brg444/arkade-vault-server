package application

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	arkadevaultv1 "github.com/brg444/arkade-runtime/internal/profile/arkadevaultv1"
	"github.com/brg444/arkade-runtime/internal/profile/vaultedlightv1"
)

func TestRouteTablesMatchProfileGoldenAndREADME(t *testing.T) {
	mounted := make(map[string][]string, len(authorizerRouteMethods))
	for path, methods := range authorizerRouteMethods {
		mounted[path] = sortedMethods(methods)
	}

	profile := map[string][]string{
		"/health": {"GET"},
		"/ready":  {"GET"},
	}
	for _, route := range append(arkadevaultv1.Definition().Routes, vaultedlightv1.Definition().Routes...) {
		profile[route.Path] = append(profile[route.Path], route.Method)
	}
	sortRouteMethods(profile)

	raw, err := os.ReadFile("testdata/http-v1-compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Routes map[string][]string `json:"routes"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	sortRouteMethods(golden.Routes)

	assertSameRouteTable(t, "mounted allowlist", mounted, "compiled profile", profile)
	assertSameRouteTable(t, "mounted allowlist", mounted, "compatibility golden", golden.Routes)

	readme, err := readREADMEHTTPRoutes("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	assertSameRouteTable(t, "mounted non-OPTIONS routes", withoutOptions(mounted), "README", readme)
}

func readREADMEHTTPRoutes(path string) (map[string][]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	section := string(raw)
	const heading = "## HTTP surface\n"
	start := strings.Index(section, heading)
	if start < 0 {
		return nil, fmt.Errorf("README HTTP surface heading is missing")
	}
	section = section[start+len(heading):]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}

	routes := make(map[string][]string)
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 3 {
			return nil, fmt.Errorf("malformed README HTTP route row: %s", line)
		}
		fields := strings.Fields(strings.NewReplacer("`", "", ",", "").Replace(strings.TrimSpace(cells[1])))
		if len(fields) < 2 || !strings.HasPrefix(fields[len(fields)-1], "/") {
			return nil, fmt.Errorf("malformed README HTTP route cell: %s", strings.TrimSpace(cells[1]))
		}
		path := fields[len(fields)-1]
		routes[path] = append(routes[path], fields[:len(fields)-1]...)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("README HTTP surface has no routes")
	}
	sortRouteMethods(routes)
	return routes, nil
}

func withoutOptions(routes map[string][]string) map[string][]string {
	out := make(map[string][]string, len(routes))
	for path, methods := range routes {
		for _, method := range methods {
			if method != "OPTIONS" {
				out[path] = append(out[path], method)
			}
		}
	}
	return out
}

func sortRouteMethods(routes map[string][]string) {
	for path := range routes {
		slices.Sort(routes[path])
	}
}

func assertSameRouteTable(t *testing.T, leftName string, left map[string][]string, rightName string, right map[string][]string) {
	t.Helper()
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("%s and %s differ:\n%s: %#v\n%s: %#v", leftName, rightName, leftName, left, rightName, right)
	}
}
