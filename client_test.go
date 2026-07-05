package cloudflaresecrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient returns a client whose requests are directed at srv instead of
// the real Cloudflare API, with a tiny retry backoff so tests stay fast.
func newTestClient(srv *httptest.Server) *cloudflareClient {
	c := newCloudflareClient("test-parent-token")
	c.baseURL = srv.URL
	c.retryBackoff = time.Millisecond
	return c
}

func writeEnvelope(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// TestDoRetriesOn429ThenSucceeds verifies transient 429s are retried and the
// Retry-After header is honored for pacing.
func TestDoRetriesOn429ThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			writeEnvelope(w, http.StatusTooManyRequests,
				`{"success":false,"errors":[{"code":10000,"message":"rate limited"}]}`)
			return
		}
		writeEnvelope(w, http.StatusOK, `{"success":true,"result":{"ok":true}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if err := c.do(context.Background(), http.MethodGet, "/x", nil, nil); err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 attempts (429 then 200), got %d", got)
	}
}

// TestDoDoesNotRetryPostOn500 verifies that an ambiguous 5xx on a POST is not
// retried, so a lost response cannot mint duplicate tokens.
func TestDoDoesNotRetryPostOn500(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeEnvelope(w, http.StatusInternalServerError,
			`{"success":false,"errors":[{"code":10000,"message":"boom"}]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.do(context.Background(), http.MethodPost, "/x", map[string]string{"a": "b"}, nil)
	if err == nil {
		t.Fatal("expected error from 500")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("POST must not be retried on 5xx; expected 1 attempt, got %d", got)
	}
}

// TestDoRetriesIdempotent5xxThenGivesUp verifies a GET is retried on 5xx up to
// the cap and then returns the error.
func TestDoRetriesIdempotent5xxThenGivesUp(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeEnvelope(w, http.StatusBadGateway, `{"success":false,"errors":[{"code":10000,"message":"bad gateway"}]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if err := c.do(context.Background(), http.MethodGet, "/x", nil, nil); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := atomic.LoadInt32(&calls); got != maxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", maxRetries+1, got)
	}
}

// TestDoParseErrorDoesNotLeakBody verifies that when the response is not a
// valid envelope, the raw body (which may contain a secret token value) is not
// included in the returned error.
func TestDoParseErrorDoesNotLeakBody(t *testing.T) {
	const secret = "v1.0-SUPERSECRETTOKENVALUE-should-not-appear"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 OK but not the expected JSON envelope, carrying a secret.
		writeEnvelope(w, http.StatusOK, `<html>token=`+secret+`</html>`)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked response body containing a secret: %v", err)
	}
}

// TestDoBoundsResponseBody verifies an oversized body is truncated by the read
// limit (the truncated, invalid JSON then fails to parse) rather than being
// read unbounded into memory.
func TestDoBoundsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Valid JSON prefix followed by far more than maxResponseBytes of junk.
		_, _ = w.Write([]byte(`{"success":true,"result":`))
		junk := strings.Repeat("A", maxResponseBytes+1024)
		_, _ = w.Write([]byte(junk))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	// Truncated at the limit, so it is not valid JSON -> parse error, and
	// crucially the process did not read the whole oversized body.
	if err := c.do(context.Background(), http.MethodGet, "/x", nil, nil); err == nil {
		t.Fatal("expected parse error on truncated oversized body")
	}
}

// TestCfErrorIsNotFound verifies the 404 classification used by idempotent
// revocation.
func TestCfErrorIsNotFound(t *testing.T) {
	if !(&cfError{StatusCode: http.StatusNotFound}).isNotFound() {
		t.Fatal("404 cfError should be classified as not-found")
	}
	if (&cfError{StatusCode: http.StatusForbidden}).isNotFound() {
		t.Fatal("403 cfError must not be classified as not-found")
	}
}
