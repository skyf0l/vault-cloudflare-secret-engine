package cloudflaresecrets

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestAcceptance_R2Credentials mints an R2-scoped token through the backend
// against the live Cloudflare API and verifies the derived S3 keypair. It does
// not exercise the S3 data plane itself (that needs no plugin code and would
// add an S3 client dependency); the derived keypair has been confirmed to work
// against a real R2 bucket out-of-band. [M11]
//
// Requires: VAULT_ACC=1, CLOUDFLARE_TEST_R2=1, CLOUDFLARE_ACCOUNT_ID,
// CLOUDFLARE_API_TOKEN (holding a "Workers R2 Storage ... Write" group so it can
// grant it), and R2 enabled on the account.
func TestAcceptance_R2Credentials(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test; set VAULT_ACC=1 to run")
	}
	if os.Getenv("CLOUDFLARE_TEST_R2") == "" {
		t.Skip("set CLOUDFLARE_TEST_R2=1 (with R2 enabled and an R2-capable parent token) to run")
	}
	accountID := requireEnv(t, "CLOUDFLARE_ACCOUNT_ID")
	parentToken := requireEnv(t, "CLOUDFLARE_API_TOKEN")
	ctx := context.Background()

	accScope := tokenScope{Type: tokenTypeAccount, AccountID: accountID}
	pgs, err := newCloudflareClient(parentToken).listPermissionGroups(ctx, accScope)
	if err != nil {
		t.Fatalf("list permission groups: %v", err)
	}
	var r2WriteID string
	for _, pg := range pgs {
		if strings.Contains(pg.Name, "R2 Storage") && strings.Contains(pg.Name, "Write") {
			r2WriteID = pg.ID
			break
		}
	}
	if r2WriteID == "" {
		t.Skip("parent token cannot grant an R2 storage write group")
	}

	b, storage := newTestBackendWithAPI(t, "") // real API
	mustWrite(t, ctx, b, storage, "config", map[string]interface{}{
		"cloudflare_account_id": accountID,
		"cloudflare_api_token":  parentToken,
	})
	mustWrite(t, ctx, b, storage, "role/r2", map[string]interface{}{
		"token_type":        "account",
		"policies":          fmt.Sprintf(`[{"permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]`, r2WriteID, accountID),
		"r2_s3_credentials": true,
		"ttl":               "5m",
		"max_ttl":           "10m",
	})

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/r2", Storage: storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("creds/r2: err=%v resp=%v", err, resp)
	}
	// Always revoke the minted token.
	t.Cleanup(func() {
		_, _ = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.RevokeOperation, Path: "creds/r2", Storage: storage, Secret: resp.Secret,
		})
	})

	tokenValue, _ := resp.Data["token"].(string)
	tokenID, _ := resp.Data["token_id"].(string)
	ak, _ := resp.Data["r2_access_key_id"].(string)
	sk, _ := resp.Data["r2_secret_access_key"].(string)
	ep, _ := resp.Data["r2_endpoint"].(string)

	if ak != tokenID {
		t.Fatalf("r2_access_key_id (%s) must equal token_id (%s)", ak, tokenID)
	}
	if sk != r2SecretAccessKey(tokenValue) {
		t.Fatal("r2_secret_access_key is not the SHA-256 of the token value")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sk) {
		t.Fatalf("r2_secret_access_key is not 64-char hex: %q", sk)
	}
	if want := r2Endpoint(accountID); ep != want {
		t.Fatalf("r2_endpoint = %q, want %q", ep, want)
	}
}
