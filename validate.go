package cloudflaresecrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
)

// cloudflareIDPattern matches Cloudflare's 32-character lowercase-hex resource
// identifiers (account IDs, zone IDs, token IDs).
var cloudflareIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// validateAccountID rejects anything that is not a Cloudflare account ID. This
// both catches misconfiguration early and prevents request-path injection: the
// account ID is interpolated into the Cloudflare API request path, so a value
// such as "x/../../user" could otherwise retarget the request.
func validateAccountID(id string) error {
	if !cloudflareIDPattern.MatchString(id) {
		return fmt.Errorf("account_id must be a 32-character hex Cloudflare account ID")
	}
	return nil
}

// validateIPRestrictions ensures every entry is a valid IP or IPv4/IPv6 CIDR.
// Validating at write time means a typo or an empty element (e.g. from a
// trailing comma) is rejected up front, instead of being silently dropped and
// weakening a deny list the operator believes is in force.
func validateIPRestrictions(field string, entries []string) error {
	for _, e := range entries {
		if _, _, err := net.ParseCIDR(e); err == nil {
			continue
		}
		if net.ParseIP(e) != nil {
			continue
		}
		return fmt.Errorf("%s: %q is not a valid IP address or CIDR", field, e)
	}
	return nil
}

// validateResources ensures a policy's resources is a non-empty JSON object.
// The previous raw-length check accepted {}, null, [], and scalars, none of
// which are valid Cloudflare resource maps and all of which would fail only
// later at token-generation time.
func validateResources(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return fmt.Errorf("resources is required")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return fmt.Errorf("resources must be a JSON object")
	}
	if len(m) == 0 {
		return fmt.Errorf("resources must not be empty")
	}
	return nil
}
