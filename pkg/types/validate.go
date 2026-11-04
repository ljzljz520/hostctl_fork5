package types

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

var (
	// ErrInvalidHostname when a hostname/domain cannot be safely serialized
	// into a hosts file line.
	ErrInvalidHostname = errors.New("invalid hostname")

	// ErrInvalidProfileName when a profile name cannot be safely serialized
	// into a "# profile.<status> <name>" header.
	ErrInvalidProfileName = errors.New("invalid profile name")

	// ErrInvalidStatus when a profile status is not one of the known values.
	ErrInvalidStatus = errors.New("invalid profile status")

	// ErrInvalidRow when a default-profile row cannot be safely serialized.
	ErrInvalidRow = errors.New("invalid hosts row")
)

// ValidateHostname checks a single hostname or domain (including the Docker
// domain suffix) before it is serialized into a hosts file line.
//
// The hosts file grammar uses three structural separators: line breaks end a
// record, whitespace separates fields and '#' starts a comment. A value
// containing any of them can forge extra routes, headers or comments, so it is
// rejected. Single-label local names (e.g. "myrouter", "loc") and underscores
// (common in Docker container names) are intentionally allowed.
func ValidateHostname(host string) error {
	if host == "" {
		return fmt.Errorf("%w: hostname is empty", ErrInvalidHostname)
	}

	for _, r := range host {
		if err := validateHostRune(host, r); err != nil {
			return err
		}
	}

	return nil
}

func validateHostRune(host string, r rune) error {
	switch {
	case unicode.IsControl(r):
		return fmt.Errorf("%w: %q contains control character %q", ErrInvalidHostname, host, r)
	case unicode.IsSpace(r):
		return fmt.Errorf("%w: %q contains whitespace %q", ErrInvalidHostname, host, r)
	case r == '#':
		return fmt.Errorf("%w: %q contains comment marker %q", ErrInvalidHostname, host, r)
	}

	return nil
}

// ValidateProfileName checks a profile name before it is written to a
// "# profile.<status> <name>" header. Spaces are allowed because existing
// profiles may contain them, but line breaks, control characters and the
// comment marker are rejected: they could forge headers or escape a disabled
// block as an enabled one.
func ValidateProfileName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: profile name is empty", ErrInvalidProfileName)
	}

	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %q contains control character %q", ErrInvalidProfileName, name, r)
		}

		if r == '#' {
			return fmt.Errorf("%w: %q contains comment marker %q", ErrInvalidProfileName, name, r)
		}
	}

	return nil
}

// ValidateRoute checks the IP and every hostname of a route before it is
// stored or serialized.
func ValidateRoute(r *Route) error {
	if r == nil {
		return fmt.Errorf("%w: route is nil", ErrInvalidIP)
	}

	if r.IP == nil {
		return fmt.Errorf("%w: ip is empty", ErrInvalidIP)
	}

	if _, ok := netip.AddrFromSlice(r.IP); !ok {
		return fmt.Errorf("%w '%s'", ErrInvalidIP, r.IP)
	}

	for _, host := range r.HostNames {
		if err := ValidateHostname(host); err != nil {
			return err
		}
	}

	return nil
}

// Validate checks the profile name, status and routes before the profile is
// stored or rendered. It is the shared contract used by mutation interfaces
// and by the rendering exit.
func (p *Profile) Validate() error {
	if err := ValidateProfileName(p.Name); err != nil {
		return err
	}

	// An empty status is accepted for backward compatibility: it carries no
	// injectable content and renders as an enabled profile.
	if p.Status != "" && p.Status != Enabled && p.Status != Disabled {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, p.Status)
	}

	for _, ip := range p.IPList {
		r, ok := p.Routes[ip]
		if !ok {
			return fmt.Errorf("%w: missing route for %s", ErrInvalidIP, ip)
		}

		if err := ValidateRoute(r); err != nil {
			return err
		}
	}

	return nil
}

// ValidateRow checks a row of the default profile before it is rendered.
// Comment rows are free-form text: only line breaks (which could forge routes
// or profile headers) are rejected. Route rows must carry a valid IP and
// hostname.
func ValidateRow(row *Row) error {
	if row == nil {
		return fmt.Errorf("%w: row is nil", ErrInvalidRow)
	}

	// Blank rows render as empty lines.
	if row.Comment == "" && row.IP == "" && row.Host == "" {
		return nil
	}

	if row.Comment != "" {
		for _, r := range row.Comment {
			if r == '\n' || r == '\r' {
				return fmt.Errorf("%w: comment contains line break %q", ErrInvalidRow, r)
			}
		}

		return nil
	}

	if _, err := netip.ParseAddr(row.IP); err != nil {
		return fmt.Errorf("%w '%s': %v", ErrInvalidIP, row.IP, err)
	}

	if err := ValidateHostname(row.Host); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRow, err)
	}

	return nil
}

// Validate checks all rows of the default profile.
func (d DefaultProfile) Validate() error {
	for _, row := range d {
		if err := ValidateRow(row); err != nil {
			return err
		}
	}

	return nil
}
