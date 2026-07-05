package cloudflaresecrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestRevokeGracefulWhenConfigDeleted verifies that if the backend config is
// removed while a lease is outstanding, revocation clears the lease (returns no
// error) instead of failing forever; the Cloudflare token is reclaimed by its
// expires_on backstop. [M4/M5]
func TestRevokeGracefulWhenConfigDeleted(t *testing.T) {
	var deleteCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tokens"):
			writeEnvelope(w, http.StatusOK, `{"success":true,"result":{"id":"tok","value":"val","name":"n"}}`)
		case r.Method == http.MethodDelete:
			deleteCalled = true
			writeEnvelope(w, http.StatusOK, `{"success":true,"result":{"id":"tok"}}`)
		default:
			writeEnvelope(w, http.StatusNotFound, `{"success":false,"errors":[{"code":1,"message":"no"}]}`)
		}
	}))
	defer srv.Close()

	b, storage := newTestBackendWithAPI(t, srv.URL)
	ctx := context.Background()

	mustWrite(t, ctx, b, storage, "config", map[string]interface{}{
		"cloudflare_account_id": testAccountID,
		"cloudflare_api_token":  "parent",
	})
	mustWrite(t, ctx, b, storage, "role/r", map[string]interface{}{
		"token_type": "account",
		"policies":   `[{"permission_groups":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"resources":{"com.cloudflare.api.account.` + testAccountID + `":"*"}}]`,
	})
	minted := mustCreds(t, ctx, b, storage, "r")

	// Remove the config, then revoke the outstanding lease.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "config", Storage: storage,
	}); err != nil {
		t.Fatalf("delete config: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/r",
		Storage:   storage,
		Secret:    minted.Secret,
	})
	if err != nil {
		t.Fatalf("revoke should degrade gracefully, got error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("revoke should degrade gracefully, got error response: %v", resp)
	}
	if deleteCalled {
		t.Fatal("delete should not be attempted once the backend is deconfigured")
	}
}
