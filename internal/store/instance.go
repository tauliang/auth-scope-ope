// Instance binding validation and session cookie derivation.
//
// The session cookie for an OPE instance is named
// "__Host-authscope-ope-session-<instance-id>". The __Host- prefix requires
// the cookie to be set with Secure, Path=/, and no Domain attribute; Task 3
// enforces those attributes when it issues sessions. This file derives the
// name and validates the binding fields; it never writes cookies.
package store

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	// ErrInvalidHostname reports a hostname that is not a valid DNS name or
	// IP literal.
	ErrInvalidHostname = errors.New("store: invalid hostname")
	// ErrInvalidOrigin reports an origin that is not an exact
	// scheme://host[:port] origin.
	ErrInvalidOrigin = errors.New("store: invalid origin")
	// ErrInsecureOrigin reports a non-HTTPS origin in release mode.
	ErrInsecureOrigin = errors.New("store: origin must use https in release mode")
	// ErrOriginNotPermitted reports a non-loopback HTTP origin in
	// development mode.
	ErrOriginNotPermitted = errors.New("store: http origin permitted for loopback only in development mode")
	// ErrInvalidRPID reports a relying-party ID that is not a valid domain.
	ErrInvalidRPID = errors.New("store: invalid RP ID")
	// ErrRPIDOriginMismatch reports a relying-party ID that is neither the
	// origin host nor a parent domain of it.
	ErrRPIDOriginMismatch = errors.New("store: RP ID must match the origin host or a parent domain")
	// ErrInvalidCookieName reports a session cookie name that does not derive
	// from the instance ID.
	ErrInvalidCookieName = errors.New("store: invalid session cookie name")
	// ErrInvalidInstanceID reports a malformed instance ID.
	ErrInvalidInstanceID = errors.New("store: invalid instance ID")
	// ErrEmptyWorkspaceID reports a missing workspace ID.
	ErrEmptyWorkspaceID = errors.New("store: workspace ID is required")
)

// SessionCookiePrefix is the __Host- cookie prefix for OPE sessions. The
// full name appends the instance ID, keeping sessions unique per instance.
const SessionCookiePrefix = "__Host-authscope-ope-session-"

// DeriveSessionCookieName returns the session cookie name for an instance.
// Set it with Secure, Path=/, and no Domain attribute (enforced by the
// session code in Task 3).
func DeriveSessionCookieName(instanceID string) string {
	return SessionCookiePrefix + instanceID
}

// ValidateInstance checks an instance binding record for structural
// validity. mode is "development" or "release" and controls origin policy.
func ValidateInstance(rec InstanceRecord, mode string) error {
	if err := ValidateInstanceID(rec.InstanceID); err != nil {
		return err
	}
	if strings.TrimSpace(rec.WorkspaceID) == "" {
		return ErrEmptyWorkspaceID
	}
	if err := ValidateHostname(rec.Hostname); err != nil {
		return err
	}
	origin, err := ValidateOrigin(rec.Origin, mode)
	if err != nil {
		return err
	}
	if err := ValidateRPID(rec.RPID, origin, mode); err != nil {
		return err
	}
	if rec.SessionCookieName != DeriveSessionCookieName(rec.InstanceID) {
		return fmt.Errorf("%w: got %q", ErrInvalidCookieName, rec.SessionCookieName)
	}
	if rec.CreatedAt.IsZero() {
		return errors.New("store: instance CreatedAt is required")
	}
	return nil
}

// ValidateInstanceID checks the instance ID charset and length.
func ValidateInstanceID(id string) error {
	if id == "" || len(id) > 64 {
		return fmt.Errorf("%w: must be 1-64 characters", ErrInvalidInstanceID)
	}
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("%w: %q has invalid characters", ErrInvalidInstanceID, id)
	}
	return nil
}

// ValidateHostname accepts a DNS hostname (single label like "localhost"
// included) or an IP literal.
func ValidateHostname(host string) error {
	if host == "" {
		return fmt.Errorf("%w: empty", ErrInvalidHostname)
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("%w: too long", ErrInvalidHostname)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("%w: bad label in %q", ErrInvalidHostname, host)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: label %q", ErrInvalidHostname, label)
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return fmt.Errorf("%w: bad character in %q", ErrInvalidHostname, host)
		}
	}
	return nil
}

// ValidateOrigin requires an exact origin: scheme://host[:port] with no
// path, query, fragment, or userinfo. In release mode the scheme must be
// https. In development mode https is always allowed and http is allowed
// only for loopback hosts. It returns the parsed origin URL.
func ValidateOrigin(raw, mode string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%w: %q", ErrInvalidOrigin, raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: must not carry userinfo, query, or fragment: %q", ErrInvalidOrigin, raw)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%w: must not carry a path: %q", ErrInvalidOrigin, raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u, nil
	case "http":
		if mode == "release" {
			return nil, fmt.Errorf("%w: got %q", ErrInsecureOrigin, raw)
		}
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("%w: %q", ErrOriginNotPermitted, raw)
		}
		return u, nil
	default:
		return nil, fmt.Errorf("%w: unsupported scheme in %q", ErrInvalidOrigin, raw)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateRPID requires the relying-party ID to be a valid domain that
// equals the origin host or a parent domain of it. In development mode a
// loopback IP origin may use the same IP as its RP ID.
func ValidateRPID(rpid string, origin *url.URL, mode string) error {
	rpid = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rpid), "."))
	if rpid == "" {
		return fmt.Errorf("%w: empty", ErrInvalidRPID)
	}
	host := strings.ToLower(origin.Hostname())
	if mode != "release" && isLoopbackHost(host) && net.ParseIP(rpid) != nil && rpid == host {
		return nil
	}
	if net.ParseIP(rpid) != nil {
		return fmt.Errorf("%w: IP literals are not valid RP IDs: %q", ErrInvalidRPID, rpid)
	}
	if err := ValidateHostname(rpid); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRPID, err)
	}
	if strings.Contains(rpid, ":") || strings.Contains(rpid, "/") {
		return fmt.Errorf("%w: must be a bare domain: %q", ErrInvalidRPID, rpid)
	}
	if host == rpid || strings.HasSuffix(host, "."+rpid) {
		return nil
	}
	return fmt.Errorf("%w: RP ID %q vs origin host %q", ErrRPIDOriginMismatch, rpid, host)
}
