package cloudflaresecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// testAccountID is a syntactically valid (32-char lowercase hex) Cloudflare
// account ID for unit tests that exercise config/role writes now that the
// account ID format is validated.
const testAccountID = "0123456789abcdef0123456789abcdef"

// newTestBackend builds a backend backed by in-memory storage for unit tests.
func newTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return b, storage
}

// newTestBackendWithAPI builds a *cloudflareBackend whose Cloudflare clients are
// pointed at apiBaseURL (an httptest server), so backend flows that call the
// Cloudflare API can be exercised offline.
func newTestBackendWithAPI(t *testing.T, apiBaseURL string) (*cloudflareBackend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b := newBackend()
	b.apiBaseURL = apiBaseURL
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return b, storage
}
