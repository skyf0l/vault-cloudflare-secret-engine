package cloudflaresecrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a configured Cloudflare secrets backend. It is the entry
// point referenced by the plugin's main package.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// cloudflareBackend implements logical.Backend for minting dynamic Cloudflare
// API tokens.
type cloudflareBackend struct {
	*framework.Backend
	// lock serializes read-modify-write mutations of the config and role
	// entries. Vault core does not serialize concurrent logical requests to the
	// same storage key across a Get+Put, so without this two concurrent writes
	// could lose an update (e.g. a rotated parent token clobbered back).
	lock sync.RWMutex
	// apiBaseURL, when non-empty, overrides the Cloudflare API base URL for
	// every client this backend builds. It is a test-only seam: it is not
	// settable through any configured path, so it cannot be influenced by an
	// operator or attacker.
	apiBaseURL string
}

// newClient builds a Cloudflare client for a parent token, applying the
// backend's API base override when set (tests only).
func (b *cloudflareBackend) newClient(token string) *cloudflareClient {
	c := newCloudflareClient(token)
	if b.apiBaseURL != "" {
		c.baseURL = b.apiBaseURL
	}
	return c
}

func newBackend() *cloudflareBackend {
	b := &cloudflareBackend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathRole(b),
			[]*framework.Path{
				pathConfig(b),
				pathConfigRotateRoot(b),
				pathCreds(b),
			},
		),
		Secrets: []*framework.Secret{
			secretToken(b),
		},
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
	}

	return b
}

// clientForTokenType loads the config and builds a Cloudflare client using the
// parent credential for the requested token context (account or user). It fails
// with a clear error when that context's credentials are not configured.
func (b *cloudflareBackend) clientForTokenType(ctx context.Context, s logical.Storage, tokenType string) (*cloudflareClient, error) {
	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	token, err := config.parentTokenFor(tokenType)
	if err != nil {
		return nil, err
	}
	return b.newClient(token), nil
}

const backendHelp = `
The Cloudflare secrets engine generates dynamic, short-lived Cloudflare API
tokens. Configure it with a parent account ID and API token, then read from the
generate endpoint to mint scoped tokens. Each generated token is leased by Vault
and revoked (deleted from Cloudflare) when its lease expires.
`
