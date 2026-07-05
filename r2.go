package cloudflaresecrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// r2SecretAccessKey derives the R2 S3 Secret Access Key from a Cloudflare API
// token value: the lowercase hex SHA-256 of the token value. The paired Access
// Key ID is the token's ID. This is Cloudflare's documented scheme for using an
// API token (with R2 permissions) as S3-compatible R2 credentials, so the
// derived keypair is revoked exactly when the underlying token's lease is.
func r2SecretAccessKey(tokenValue string) string {
	sum := sha256.Sum256([]byte(tokenValue))
	return hex.EncodeToString(sum[:])
}

// r2Endpoint returns the account's S3-compatible R2 endpoint.
func r2Endpoint(accountID string) string {
	return fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)
}
