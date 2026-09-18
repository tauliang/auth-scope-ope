package e2e

// Pin subset: the fakes expose only operations pinned in the required
// capability manifest. Nothing outside the manifest reaches the wire.

import (
	"strings"
	"testing"

	"github.com/tauliang/authscope-ope/internal/coreapi"
)

func TestFakeIsManifestSubset(t *testing.T) {
	f := newJourneyFixture(t, nil)
	_ = f.fake.Handler() // populates the operation list
	manifest := coreapi.RequiredManifest()
	pinned := map[string]string{}
	for _, op := range manifest.RequiredOperations {
		pinned[op.Method+" "+op.Path] = op.Capability
	}
	if len(pinned) != 36 {
		t.Fatalf("pinned manifest has %d operations, want 36", len(pinned))
	}
	type methodPath struct{ method, path string }
	exposed := map[methodPath]bool{}
	for _, op := range f.fake.Operations() {
		exposed[methodPath{op.Method, op.Path}] = true
	}
	// The gateway authorization endpoint lives on the fake gateway, not
	// the fake AuthScope, but it is part of the same pinned surface.
	exposed[methodPath{"POST", "/v1/gateway/authorize"}] = true
	if len(exposed) == 0 {
		t.Fatalf("fake exposes no operations")
	}
	for mp := range exposed {
		key := mp.method + " " + mp.path
		capability, ok := pinned[key]
		if !ok {
			t.Fatalf("fake exposes %q, which is not in the pinned manifest", key)
		}
		t.Logf("fake %-6s %-60s pinned as %s", mp.method, mp.path, capability)
	}
	// The fake is the complete pinned surface: every pinned operation is
	// exposed, so a journey can reach any capability the contract allows.
	for key := range pinned {
		method, path, _ := strings.Cut(key, " ")
		if !exposed[methodPath{method, path}] {
			t.Fatalf("pinned operation %q is not exposed by the fake", key)
		}
	}
	t.Logf("fake exposes %d of %d pinned operations", len(exposed), len(pinned))
}
