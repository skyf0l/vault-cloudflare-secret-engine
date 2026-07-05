package cloudflaresecrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestR2SecretAccessKey is a known-answer test: the secret is the lowercase hex
// SHA-256 of the token value. SHA-256("abc") is a well-known digest.
func TestR2SecretAccessKey(t *testing.T) {
	const wantABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := r2SecretAccessKey("abc"); got != wantABC {
		t.Fatalf("r2SecretAccessKey(abc) = %q, want %q", got, wantABC)
	}
	if got := r2Endpoint(testAccountID); got != "https://"+testAccountID+".r2.cloudflarestorage.com" {
		t.Fatalf("unexpected endpoint: %q", got)
	}
}

// TestCredsR2CredentialsOptIn verifies that a role with r2_s3_credentials=true
// gets the derived keypair and endpoint in its creds response, and a role
// without it does not. [M11]
func TestCredsR2CredentialsOptIn(t *testing.T) {
	const tokID = "cafebabecafebabecafebabecafebabe"
	const tokValue = "v1.0-the-minted-token-value"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tokens") {
			writeEnvelope(w, http.StatusOK,
				`{"success":true,"result":{"id":"`+tokID+`","value":"`+tokValue+`","name":"vault-r2-1"}}`)
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		writeEnvelope(w, http.StatusNotFound, `{"success":false,"errors":[{"code":1,"message":"no"}]}`)
	}))
	defer srv.Close()

	b, storage := newTestBackendWithAPI(t, srv.URL)
	ctx := context.Background()

	mustWrite(t, ctx, b, storage, "config", map[string]interface{}{
		"cloudflare_account_id": testAccountID,
		"cloudflare_api_token":  "parent",
	})

	// Permission group referenced by ID so no live-catalog round-trip is needed.
	policies := `[{"permission_groups":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"resources":{"com.cloudflare.api.account.` + testAccountID + `":"*"}}]`

	mustWrite(t, ctx, b, storage, "role/r2", map[string]interface{}{
		"token_type":        "account",
		"policies":          policies,
		"r2_s3_credentials": true,
	})
	mustWrite(t, ctx, b, storage, "role/plain", map[string]interface{}{
		"token_type": "account",
		"policies":   policies,
	})

	// R2 role: keypair + endpoint present and correct.
	resp := mustCreds(t, ctx, b, storage, "r2")
	if resp.Data["r2_access_key_id"] != tokID {
		t.Fatalf("r2_access_key_id = %v, want token id %s", resp.Data["r2_access_key_id"], tokID)
	}
	sk, _ := resp.Data["r2_secret_access_key"].(string)
	if sk != r2SecretAccessKey(tokValue) {
		t.Fatalf("r2_secret_access_key mismatch")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sk) {
		t.Fatalf("r2_secret_access_key is not 64-char hex: %q", sk)
	}
	if resp.Data["r2_endpoint"] != r2Endpoint(testAccountID) {
		t.Fatalf("r2_endpoint = %v", resp.Data["r2_endpoint"])
	}

	// Non-R2 role: none of the R2 fields present.
	resp2 := mustCreds(t, ctx, b, storage, "plain")
	for _, k := range []string{"r2_access_key_id", "r2_secret_access_key", "r2_endpoint"} {
		if _, ok := resp2.Data[k]; ok {
			t.Fatalf("non-R2 role unexpectedly returned %q", k)
		}
	}
}

func mustCreds(t *testing.T, ctx context.Context, b logical.Backend, s logical.Storage, role string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role,
		Storage:   s,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("creds/%s: err=%v resp=%v", role, err, resp)
	}
	return resp
}
