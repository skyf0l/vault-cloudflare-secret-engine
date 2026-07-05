package cloudflaresecrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestRotateRootAccount verifies config/rotate-root discovers the parent
// token's ID via verify, rolls its value, persists the new value, and never
// returns the plaintext. [H5]
func TestRotateRootAccount(t *testing.T) {
	const (
		oldValue = "v1.0-OLD-PARENT-VALUE"
		newValue = "v1.0-NEW-ROLLED-VALUE"
		tokID    = "abcdef0123456789abcdef0123456789"
	)
	var verifyCalls, rollCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tokens/verify"):
			atomic.AddInt32(&verifyCalls, 1)
			// The verify call must authenticate with the current parent token.
			if got := r.Header.Get("Authorization"); got != "Bearer "+oldValue {
				t.Errorf("verify used %q, want bearer old value", got)
			}
			writeEnvelope(w, http.StatusOK,
				`{"success":true,"result":{"id":"`+tokID+`","status":"active"}}`)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/tokens/"+tokID+"/value"):
			atomic.AddInt32(&rollCalls, 1)
			writeEnvelope(w, http.StatusOK, `{"success":true,"result":"`+newValue+`"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeEnvelope(w, http.StatusNotFound, `{"success":false,"errors":[{"code":1,"message":"no"}]}`)
		}
	}))
	defer srv.Close()

	b, storage := newTestBackendWithAPI(t, srv.URL)
	ctx := context.Background()

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"cloudflare_account_id": testAccountID,
			"cloudflare_api_token":  oldValue,
		},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
		Data:      map[string]interface{}{"token_type": tokenTypeAccount},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate-root: err=%v resp=%v", err, resp)
	}
	if resp.Data["token_id"] != tokID || resp.Data["rotated"] != true {
		t.Fatalf("unexpected response data: %#v", resp.Data)
	}
	// The plaintext new value must never be returned.
	for k, v := range resp.Data {
		if s, ok := v.(string); ok && strings.Contains(s, newValue) {
			t.Fatalf("response field %q leaked the new token value", k)
		}
	}
	if atomic.LoadInt32(&verifyCalls) != 1 || atomic.LoadInt32(&rollCalls) != 1 {
		t.Fatalf("expected 1 verify + 1 roll, got %d verify %d roll", verifyCalls, rollCalls)
	}

	// The rolled value must be persisted so future operations use it.
	cfg, err := getConfig(ctx, storage)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	if cfg.APIToken != newValue {
		t.Fatalf("config still holds the old token value after rotation")
	}
}

// TestRotateRootUnconfiguredContext rejects rotating a context that has no
// configured credential.
func TestRotateRootUnconfiguredContext(t *testing.T) {
	b, storage := newTestBackendWithAPI(t, "http://127.0.0.1:0")
	ctx := context.Background()

	// Configure only the account context.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"cloudflare_account_id": testAccountID,
			"cloudflare_api_token":  "v",
		},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
		Data:      map[string]interface{}{"token_type": tokenTypeUser},
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error rotating an unconfigured user context, got %v", resp)
	}
}
