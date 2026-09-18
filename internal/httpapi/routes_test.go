package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var validAuth = map[string]bool{
	"none": true, "bootstrap-ceremony": true, "founder-session": true,
	"cli-token": true, "redirect-callback": true,
}

var validIdempotency = map[string]bool{
	"none": true, "caller-key": true, "server-derived": true,
}

// TestRouteMatrixWellFormed asserts the matrix is internally consistent:
// no duplicate method+path, known enum values, and posture invariants
// that hold across the product.
func TestRouteMatrixWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, route := range RouteMatrix {
		if route.Method == "" || route.Path == "" {
			t.Fatalf("route with empty method or path: %+v", route)
		}
		key := route.Method + " " + route.Path
		if seen[key] {
			t.Fatalf("duplicate matrix entry: %s", key)
		}
		seen[key] = true
		if !validAuth[route.Auth] {
			t.Fatalf("route %s has unknown auth %q", key, route.Auth)
		}
		if !validIdempotency[route.Idempotency] {
			t.Fatalf("route %s has unknown idempotency %q", key, route.Idempotency)
		}
		if route.Replay == "" {
			t.Fatalf("route %s has no replay note", key)
		}
		// Every state-changing founder route requires the session CSRF
		// token.
		if route.Auth == "founder-session" && (route.Method == "POST" || route.Method == "PUT") && !route.CSRF {
			t.Fatalf("route %s is a founder mutation without CSRF", key)
		}
		// Every mutation carries idempotency, caller-supplied or
		// server-derived.
		if (route.Method == "POST" || route.Method == "PUT") && route.Auth == "founder-session" && route.Idempotency == "none" {
			t.Fatalf("route %s is a founder mutation without idempotency", key)
		}
		// Pre-session ceremony routes cannot require the session CSRF
		// token: the session does not exist yet.
		if (route.Auth == "none" || route.Auth == "bootstrap-ceremony" || route.Auth == "redirect-callback") && route.CSRF {
			t.Fatalf("route %s requires CSRF without a session", key)
		}
	}
}

// TestRouteMatrixMatchesRegistrations is the drift guard: every
// mux.HandleFunc call site in the package must have exactly one matrix
// entry with the same method and path. Adding a route, or swapping one
// route for another, without updating RouteMatrix fails here.
func TestRouteMatrixMatchesRegistrations(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if filepath.Base(name) == "routes.go" {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HandleFunc" {
				return true
			}
			if len(call.Args) == 0 {
				t.Fatalf("HandleFunc call without arguments in %s", name)
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("HandleFunc pattern is not a string literal in %s", name)
			}
			pattern := strings.Trim(lit.Value, `"`)
			method, path, found := strings.Cut(pattern, " ")
			if !found || method == "" || path == "" {
				t.Fatalf("HandleFunc pattern %q is not \"METHOD /path\" in %s", pattern, name)
			}
			registered[method+" "+path] = true
			return true
		})
	}
	matrix := map[string]bool{}
	for _, route := range RouteMatrix {
		matrix[route.Method+" "+route.Path] = true
	}
	for key := range registered {
		if !matrix[key] {
			t.Errorf("route %s is registered but missing from RouteMatrix", key)
		}
	}
	for key := range matrix {
		if !registered[key] {
			t.Errorf("route %s is in RouteMatrix but not registered", key)
		}
	}
}

// TestRouteMatrixUnconditionalReachable asserts the routes that need no
// optional services are served by the mux built from minimal test deps.
func TestRouteMatrixUnconditionalReachable(t *testing.T) {
	handler := New(testDeps())
	unconditional := []RoutePosture{
		{Method: "GET", Path: "/healthz"},
		{Method: "GET", Path: "/readyz"},
		{Method: "GET", Path: "/api/v1/bootstrap"},
		{Method: "POST", Path: "/api/v1/bootstrap/begin"},
		{Method: "POST", Path: "/api/v1/auth/register/begin"},
		{Method: "POST", Path: "/api/v1/auth/register/finish"},
		{Method: "POST", Path: "/api/v1/bootstrap/recovery/begin"},
		{Method: "POST", Path: "/api/v1/bootstrap/complete"},
		{Method: "POST", Path: "/api/v1/auth/login/begin"},
		{Method: "POST", Path: "/api/v1/auth/login/finish"},
	}
	for _, want := range unconditional {
		found := false
		for _, route := range RouteMatrix {
			if route.Method == want.Method && route.Path == want.Path {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unconditional route %s %s missing from matrix", want.Method, want.Path)
		}
		req := httptest.NewRequest(want.Method, want.Path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("route %s %s not registered on the mux", want.Method, want.Path)
		}
	}
}
