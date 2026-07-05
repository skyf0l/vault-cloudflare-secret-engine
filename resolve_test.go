package cloudflaresecrets

import (
	"encoding/json"
	"strings"
	"testing"
)

func policyByName(name string) []policy {
	return []policy{{
		Effect:           "allow",
		Resources:        json.RawMessage(`{"com.cloudflare.api.account.abc":"*"}`),
		PermissionGroups: []permissionGroup{{Name: name}},
	}}
}

// TestResolvePermissionGroupsUnique resolves a name that maps to a single ID.
func TestResolvePermissionGroupsUnique(t *testing.T) {
	catalog := []permissionGroup{
		{ID: "id-dns", Name: "DNS Write"},
		{ID: "id-zone", Name: "Zone Read"},
	}
	p := policyByName("DNS Write")
	if err := resolvePermissionGroups(p, catalog); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p[0].PermissionGroups[0].ID != "id-dns" || p[0].PermissionGroups[0].Name != "" {
		t.Fatalf("unexpected resolution: %#v", p[0].PermissionGroups[0])
	}
}

// TestResolvePermissionGroupsAmbiguous rejects a name shared by multiple
// distinct IDs instead of silently picking one. [H4]
func TestResolvePermissionGroupsAmbiguous(t *testing.T) {
	catalog := []permissionGroup{
		{ID: "id-acct-dns", Name: "DNS Write"},
		{ID: "id-zone-dns", Name: "DNS Write"}, // same display name, different group
	}
	err := resolvePermissionGroups(policyByName("DNS Write"), catalog)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguity error, got: %v", err)
	}
}

// TestResolvePermissionGroupsDuplicateSameID treats a name repeated with the
// same ID as unambiguous (Cloudflare can list a group more than once).
func TestResolvePermissionGroupsDuplicateSameID(t *testing.T) {
	catalog := []permissionGroup{
		{ID: "id-dns", Name: "DNS Write"},
		{ID: "id-dns", Name: "DNS Write"},
	}
	if err := resolvePermissionGroups(policyByName("DNS Write"), catalog); err != nil {
		t.Fatalf("duplicate-with-same-id should resolve, got: %v", err)
	}
}

// TestResolvePermissionGroupsUnknown errors on a name not present in the catalog.
func TestResolvePermissionGroupsUnknown(t *testing.T) {
	err := resolvePermissionGroups(policyByName("No Such Group"), []permissionGroup{{ID: "x", Name: "DNS Write"}})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown-name error, got: %v", err)
	}
}
