package cloudflaresecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// cloudflareAPIBase is the root of the Cloudflare v4 REST API.
const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

const (
	// maxResponseBytes bounds how much of a Cloudflare response body is read
	// into memory, protecting the Vault process from a malicious or
	// malfunctioning endpoint returning an unbounded body. Token responses are
	// a few KB at most.
	maxResponseBytes = 2 << 20 // 2 MiB

	// maxRetries is the number of additional attempts made after the first for
	// transiently-failing requests (429 / 5xx / transport errors).
	maxRetries = 3

	// defaultRetryBackoff is the initial wait before the first retry; it
	// doubles each subsequent attempt unless the server sends Retry-After.
	defaultRetryBackoff = 250 * time.Millisecond
)

// Token contexts. Cloudflare mints either account-owned tokens (tied to a
// service, created under /accounts/{id}/tokens) or user-owned tokens (tied to
// an individual, created under /user/tokens). Permission groups and some
// operations are only available in one context or the other.
const (
	tokenTypeAccount = "account"
	tokenTypeUser    = "user"
)

// tokenScope identifies which Cloudflare context a token operation targets.
type tokenScope struct {
	Type      string // tokenTypeAccount or tokenTypeUser
	AccountID string // required for account-owned tokens
}

// basePath returns the API path prefix for this scope.
func (s tokenScope) basePath() (string, error) {
	switch s.Type {
	case tokenTypeUser:
		return "/user", nil
	case tokenTypeAccount, "":
		if s.AccountID == "" {
			return "", errors.New("account_id is required for account-owned tokens")
		}
		return "/accounts/" + s.AccountID, nil
	default:
		return "", fmt.Errorf("invalid token_type %q (must be %q or %q)", s.Type, tokenTypeAccount, tokenTypeUser)
	}
}

// cloudflareClient wraps the Cloudflare API token endpoints. It authenticates
// with a parent API token allowed to mint and delete other tokens.
type cloudflareClient struct {
	apiToken   string
	baseURL    string
	httpClient *http.Client
	// retryBackoff is the initial backoff before the first retry. Zero means
	// defaultRetryBackoff; tests set it small to stay fast.
	retryBackoff time.Duration
}

func newCloudflareClient(apiToken string) *cloudflareClient {
	return &cloudflareClient{
		apiToken:     apiToken,
		baseURL:      cloudflareAPIBase,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		retryBackoff: defaultRetryBackoff,
	}
}

// cfError is a Cloudflare API error carrying the HTTP status and the first
// Cloudflare error code/message, so callers can react to specific conditions
// (for example, treating a 404 on delete as already-gone).
type cfError struct {
	StatusCode int
	Code       int
	Message    string
}

func (e *cfError) Error() string {
	if e.Code != 0 || e.Message != "" {
		return fmt.Sprintf("cloudflare API error (status %d): code %d: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("cloudflare API request failed with status %d", e.StatusCode)
}

// isNotFound reports whether the error signals that the target resource no
// longer exists (HTTP 404), so an operation such as delete can be treated as
// already complete.
func (e *cfError) isNotFound() bool {
	return e.StatusCode == http.StatusNotFound
}

// idempotent reports whether a request method is safe to retry after a
// transient failure without risking a duplicate side effect. POST is excluded
// because a lost response could hide a token that was actually created.
func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodHead:
		return true
	default:
		return false
	}
}

// retryAfterHeader parses a Retry-After header expressed as a number of
// seconds. It ignores the HTTP-date form and any unparseable value.
func retryAfterHeader(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// cfAPIError mirrors a single entry of the Cloudflare "errors" array.
type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfResponse is the standard Cloudflare API envelope.
type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// permissionGroup is a named bundle of permissions. In a policy only the ID is
// required; Name is accepted on input so operators can reference groups by
// human-readable name and let the plugin resolve them.
type permissionGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// policy is a single access policy attached to a token. Resources is passed
// through verbatim so the full Cloudflare resource model (account, zone,
// all-zones, user, r2, ...) is supported.
type policy struct {
	Effect           string            `json:"effect"`
	Resources        json.RawMessage   `json:"resources"`
	PermissionGroups []permissionGroup `json:"permission_groups"`
}

// requestIP is the client-IP restriction on a token.
type requestIP struct {
	In    []string `json:"in,omitempty"`
	NotIn []string `json:"not_in,omitempty"`
}

// tokenCondition carries optional token-level conditions (currently only the
// client-IP restriction).
type tokenCondition struct {
	RequestIP *requestIP `json:"request_ip,omitempty"`
}

// createTokenRequest is the body for POST .../tokens.
type createTokenRequest struct {
	Name      string          `json:"name"`
	Policies  []policy        `json:"policies"`
	Condition *tokenCondition `json:"condition,omitempty"`
	ExpiresOn string          `json:"expires_on,omitempty"`
}

// tokenResult is the relevant subset of the create-token response.
type tokenResult struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// do performs an authenticated request and unwraps the response envelope,
// retrying transient failures (429 / 5xx / transport errors) with backoff.
// Non-idempotent methods (POST) are not retried on ambiguous failures so a
// lost response cannot cause a duplicate token to be minted.
func (c *cloudflareClient) do(ctx context.Context, method, path string, body, out interface{}) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyBytes = b
	}

	base := c.baseURL
	if base == "" {
		base = cloudflareAPIBase
	}
	url := base + path

	backoff := c.retryBackoff
	if backoff <= 0 {
		backoff = defaultRetryBackoff
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		status, retryAfter, err := c.doOnce(ctx, method, url, bodyBytes, out)
		if err == nil {
			return nil
		}
		lastErr = err

		// status == 0 indicates a transport error (no HTTP response).
		transient := status == 0 || status == http.StatusTooManyRequests || status >= 500
		allowRetry := status == http.StatusTooManyRequests || idempotent(method)
		if !transient || !allowRetry || attempt >= maxRetries {
			return lastErr
		}

		wait := backoff
		if retryAfter > 0 {
			wait = retryAfter
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		backoff *= 2
	}
}

// doOnce performs a single HTTP attempt. It returns the HTTP status code (0 on
// a transport error), the server's Retry-After hint if any, and the error (nil
// on success). On success it unmarshals the result into out.
func (c *cloudflareClient) doOnce(ctx context.Context, method, url string, bodyBytes []byte, out interface{}) (int, time.Duration, error) {
	var reqBody io.Reader
	if bodyBytes != nil {
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	// Bound the read: token responses are tiny, and an unbounded body from a
	// misbehaving endpoint must not exhaust Vault's memory.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, retryAfterHeader(resp), err
	}

	var cfResp cfResponse
	if err := json.Unmarshal(data, &cfResp); err != nil {
		// The body is not the expected envelope. Do NOT echo it: token-endpoint
		// responses can contain a freshly minted secret token value.
		return resp.StatusCode, retryAfterHeader(resp),
			fmt.Errorf("cloudflare: failed to parse response (status %d)", resp.StatusCode)
	}

	if !cfResp.Success {
		apiErr := &cfError{StatusCode: resp.StatusCode}
		if len(cfResp.Errors) > 0 {
			apiErr.Code = cfResp.Errors[0].Code
			apiErr.Message = cfResp.Errors[0].Message
		}
		return resp.StatusCode, retryAfterHeader(resp), apiErr
	}

	if out != nil && len(cfResp.Result) > 0 {
		if err := json.Unmarshal(cfResp.Result, out); err != nil {
			return resp.StatusCode, 0, err
		}
	}
	return resp.StatusCode, 0, nil
}

// listPermissionGroups returns the permission groups available in a scope.
func (c *cloudflareClient) listPermissionGroups(ctx context.Context, scope tokenScope) ([]permissionGroup, error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	var pgs []permissionGroup
	if err := c.do(ctx, http.MethodGet, base+"/tokens/permission_groups", nil, &pgs); err != nil {
		return nil, err
	}
	return pgs, nil
}

// createToken mints a new token in the given scope.
func (c *cloudflareClient) createToken(ctx context.Context, scope tokenScope, req *createTokenRequest) (*tokenResult, error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	var res tokenResult
	if err := c.do(ctx, http.MethodPost, base+"/tokens", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// deleteToken revokes a previously created token by ID in the given scope.
func (c *cloudflareClient) deleteToken(ctx context.Context, scope tokenScope, tokenID string) error {
	base, err := scope.basePath()
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, base+"/tokens/"+tokenID, nil, nil)
}
