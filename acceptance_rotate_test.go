package cloudflaresecrets

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestAcceptance_RotateRoot validates config/rotate-root against the live
// Cloudflare API through the real handler path.
//
// It is DESTRUCTIVE and opt-in: rotate-root rolls the configured parent token's
// value in place, and the plugin deliberately never returns that new value, so
// after this test the token supplied via CLOUDFLARE_API_TOKEN is invalidated and
// its new value is only recoverable from Vault storage. Run it ONLY with a
// throwaway token you are willing to discard.
//
// Requires: VAULT_ACC=1, CLOUDFLARE_ROTATE_ROOT_DESTRUCTIVE=1,
// CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN (a top-level token holding
// "API Tokens Write" — only such a token can roll itself; a token minted via the
// API cannot, as Cloudflare forbids sub-tokens from managing tokens).
func TestAcceptance_RotateRoot(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test; set VAULT_ACC=1 to run")
	}
	if os.Getenv("CLOUDFLARE_ROTATE_ROOT_DESTRUCTIVE") == "" {
		t.Skip("destructive: rolls (and thus invalidates) CLOUDFLARE_API_TOKEN; set CLOUDFLARE_ROTATE_ROOT_DESTRUCTIVE=1 with a disposable token to run")
	}

	accountID := requireEnv(t, "CLOUDFLARE_ACCOUNT_ID")
	parentToken := requireEnv(t, "CLOUDFLARE_API_TOKEN")
	ctx := context.Background()

	// Record the parent token's own ID so we can assert rotate-root targets it.
	wantID, err := newCloudflareClient(parentToken).verifyToken(ctx, tokenScope{Type: tokenTypeAccount, AccountID: accountID})
	if err != nil {
		t.Fatalf("verify parent token: %v", err)
	}

	b, storage := newTestBackendWithAPI(t, "") // "" => real Cloudflare API
	mustWrite(t, ctx, b, storage, "config", map[string]interface{}{
		"cloudflare_account_id": accountID,
		"cloudflare_api_token":  parentToken,
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
		Data:      map[string]interface{}{"token_type": tokenTypeAccount},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}
	if resp.Data["token_id"] != wantID {
		t.Fatalf("rotate-root token_id=%v, want %s", resp.Data["token_id"], wantID)
	}

	// The old value must no longer verify; the persisted new value must work,
	// proven by a second rotation succeeding through the backend.
	if _, err := newCloudflareClient(parentToken).verifyToken(ctx, tokenScope{Type: tokenTypeAccount, AccountID: accountID}); err == nil {
		t.Fatal("old parent token still verifies after rotation")
	}
	resp2, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
		Data:      map[string]interface{}{"token_type": tokenTypeAccount},
	})
	if err != nil || (resp2 != nil && resp2.IsError()) {
		t.Fatalf("second rotate-root (persisted new value must work): err=%v resp=%v", err, resp2)
	}
}
