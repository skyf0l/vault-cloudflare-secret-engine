package cloudflaresecrets

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestValidateAccountID(t *testing.T) {
	valid := []string{
		"0123456789abcdef0123456789abcdef",
	}
	invalid := []string{
		"",                                  // empty
		"0123456789ABCDEF0123456789abcdef",  // uppercase
		"0123456789abcdef0123456789abcde",   // 31 chars
		"0123456789abcdef0123456789abcdef0", // 33 chars
		"x/../../user",                      // path traversal
		"acct?foo=bar",                      // query injection
	}
	for _, v := range valid {
		if err := validateAccountID(v); err != nil {
			t.Errorf("validateAccountID(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range invalid {
		if err := validateAccountID(v); err == nil {
			t.Errorf("validateAccountID(%q) = nil, want error", v)
		}
	}
}

func TestValidateIPRestrictions(t *testing.T) {
	if err := validateIPRestrictions("f", []string{"203.0.113.0/24", "2001:db8::/32", "203.0.113.7"}); err != nil {
		t.Errorf("valid CIDRs/IPs rejected: %v", err)
	}
	for _, bad := range [][]string{
		{"203.0.113.0/33"}, // impossible mask
		{"not-an-ip"},
		{""},              // empty element (trailing comma)
		{"10.0.0.0/8", ""}, // one good, one empty -> must still reject
	} {
		if err := validateIPRestrictions("f", bad); err == nil {
			t.Errorf("validateIPRestrictions(%v) = nil, want error", bad)
		}
	}
}

func TestValidateResources(t *testing.T) {
	if err := validateResources(json.RawMessage(`{"com.cloudflare.api.account.zone.abc":"*"}`)); err != nil {
		t.Errorf("valid resources rejected: %v", err)
	}
	for _, bad := range []string{`{}`, `null`, `[]`, `"str"`, `123`, ``} {
		if err := validateResources(json.RawMessage(bad)); err == nil {
			t.Errorf("validateResources(%q) = nil, want error", bad)
		}
	}
}

// TestPathRolesWriteRejectsBadInput exercises the validators through the actual
// role-write handler, confirming bad input fails at write time (not later).
func TestPathRolesWriteRejectsBadInput(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	goodPolicies := `[{"permission_groups":[{"name":"DNS Write"}],"resources":{"com.cloudflare.api.account.zone.abc":"*"}}]`

	cases := []struct {
		name string
		data map[string]interface{}
	}{
		{"bad account_id", map[string]interface{}{"token_type": "account", "account_id": "x/../../user", "policies": goodPolicies}},
		{"bad cidr", map[string]interface{}{"policies": goodPolicies, "request_ip_in": "not-an-ip"}},
		{"empty resources", map[string]interface{}{"policies": `[{"permission_groups":[{"name":"DNS Write"}],"resources":{}}]`}},
		{"null resources", map[string]interface{}{"policies": `[{"permission_groups":[{"name":"DNS Write"}],"resources":null}]`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "role/r",
				Storage:   storage,
				Data:      tc.data,
			})
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			if resp == nil || !resp.IsError() {
				t.Fatalf("expected an error response, got %v", resp)
			}
		})
	}
}
