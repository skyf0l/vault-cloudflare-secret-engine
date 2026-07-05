package cloudflaresecrets

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// cloudflareTokenType is the secret type registered for generated tokens.
const cloudflareTokenType = "cloudflare_token"

func secretToken(b *cloudflareBackend) *framework.Secret {
	return &framework.Secret{
		Type: cloudflareTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The Cloudflare API token value.",
			},
			"token_id": {
				Type:        framework.TypeString,
				Description: "The Cloudflare token identifier.",
			},
		},
		Revoke: b.secretTokenRevoke,
		Renew:  b.secretTokenRenew,
	}
}

// secretTokenRevoke deletes the Cloudflare token when its lease expires or is
// explicitly revoked.
func (b *cloudflareBackend) secretTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID, ok := req.Secret.InternalData["token_id"].(string)
	if !ok || tokenID == "" {
		// Corrupted or legacy lease with no token ID: there is nothing we can
		// delete. Clear the lease rather than wedging it; any real token dies at
		// its Cloudflare-side expires_on backstop.
		b.Logger().Warn("cloudflare token secret missing token_id; cannot revoke, relying on expiry backstop")
		return nil, nil
	}

	scope := tokenScope{}
	if v, ok := req.Secret.InternalData["token_type"].(string); ok {
		scope.Type = v
	}
	if v, ok := req.Secret.InternalData["account_id"].(string); ok {
		scope.AccountID = v
	}

	// Build the client from current config. If the backend was deconfigured or
	// the parent credential for this context was removed while leases were
	// outstanding, we cannot call Cloudflare — clear the lease and let the
	// expires_on backstop reclaim the token, instead of failing revocation
	// forever and wedging the lease.
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		b.Logger().Warn("cloudflare backend not configured at revoke; relying on token expiry backstop", "token_id", tokenID)
		return nil, nil
	}
	token, err := config.parentTokenFor(scope.Type)
	if err != nil {
		b.Logger().Warn("parent credential no longer configured; cannot revoke, relying on token expiry backstop", "token_id", tokenID, "token_type", scope.Type)
		return nil, nil
	}

	if err := b.newClient(token).deleteToken(ctx, scope, tokenID); err != nil {
		return nil, fmt.Errorf("error revoking cloudflare token %s: %w", tokenID, err)
	}
	b.Logger().Info("revoked cloudflare token", "token_id", tokenID, "token_type", scope.Type)
	return nil, nil
}

// secretTokenRenew extends the Vault lease within the bounds fixed at issuance.
// The Cloudflare-side expiry was set to max_ttl at creation, so MaxTTL must be
// the same value used then — not the current config — otherwise the lease could
// outlive the (already expired) Cloudflare token.
func (b *cloudflareBackend) secretTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	if ttl := internalDuration(req.Secret.InternalData["ttl_seconds"]); ttl > 0 {
		resp.Secret.TTL = ttl
	}
	if maxTTL := internalDuration(req.Secret.InternalData["max_ttl_seconds"]); maxTTL > 0 {
		resp.Secret.MaxTTL = maxTTL
	}
	return resp, nil
}

// internalDuration converts a seconds value stored in a secret's InternalData
// (which round-trips through JSON, so numbers come back as float64) into a
// time.Duration. Unknown or missing values yield 0.
func internalDuration(v interface{}) time.Duration {
	switch n := v.(type) {
	case float64:
		return time.Duration(n) * time.Second
	case int64:
		return time.Duration(n) * time.Second
	case int:
		return time.Duration(n) * time.Second
	default:
		return 0
	}
}
