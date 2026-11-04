package types

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

const disabledPrefix = "# "

// Profile contains all data of a single profile.
type Profile struct {
	Name   string
	Status Status
	IPList []string
	Routes map[string]*Route
}

// String returns a string representation of the profile.
func (p *Profile) String() string {
	return fmt.Sprintf("[%s]%s", p.Status, p.Name)
}

// GetStatus returns a string value of ProfileStatus.
func (p *Profile) GetStatus() string {
	return string(p.Status)
}

func (p *Profile) appendIP(n string) {
	for _, c := range p.IPList {
		if c == n {
			return
		}
	}

	p.IPList = append(p.IPList, n)
}

// AddRoute adds a single route to the profile. It returns an error without
// mutating the profile when the route is not safe to serialize.
func (p *Profile) AddRoute(route *Route) error {
	return p.AddRoutes([]*Route{route})
}

// AddRoutes adds non duplicated routes to a profile. The whole batch is
// validated before any mutation, so a single invalid route (for example a
// hostname containing a line break) leaves the profile untouched.
func (p *Profile) AddRoutes(routes []*Route) error {
	for _, r := range routes {
		if err := ValidateRoute(r); err != nil {
			return err
		}
	}

	if p.Routes == nil {
		p.Routes = map[string]*Route{}
	}

	for _, r := range routes {
		ip := r.IP.String()
		if p.Routes[ip] == nil {
			p.appendIP(ip)
			p.Routes[ip] = &Route{
				IP:        net.ParseIP(ip),
				HostNames: uniqueStrings(r.HostNames),
			}
		} else {
			p.Routes[ip].HostNames = uniqueStrings(append(p.Routes[ip].HostNames, r.HostNames...))
		}
	}

	return nil
}

// RemoveHostnames removes multiple hostnames of a profile.
func (p *Profile) RemoveHostnames(hostnames []string) {
	for _, h := range hostnames {
		for _, ip := range p.IPList {
			p.Routes[ip].HostNames = remove(p.Routes[ip].HostNames, h)
			if len(p.Routes[ip].HostNames) == 0 {
				delete(p.Routes, ip)
				p.IPList = remove(p.IPList, ip)
			}
		}
	}
}

// GetHostNames returns a list of all hostnames of the given ip.
func (p *Profile) GetHostNames(ip string) ([]string, error) {
	key := net.ParseIP(ip)
	if key == nil {
		return nil, fmt.Errorf("%w '%s'", ErrInvalidIP, ip)
	}

	hosts, ok := p.Routes[key.String()]
	if !ok {
		return nil, fmt.Errorf("%w: %s[%s] ", ErrNotPresentIP, key, p.Name)
	}

	return hosts.HostNames, nil
}

// GetAllHostNames returns all hostnames of the profile.
func (p *Profile) GetAllHostNames() []string {
	list := []string{}

	if p.IPList == nil {
		return list
	}

	for _, ip := range p.IPList {
		list = append(list, p.Routes[ip].HostNames...)
	}

	return list
}

// Render writes the profile content to the given StringWriter.
// The profile is validated first so content built by direct manipulation of
// the struct (for instance by Go package callers) cannot inject routes or
// forged headers at the rendering exit.
func (p *Profile) Render(w io.StringWriter) error {
	if err := p.Validate(); err != nil {
		return err
	}

	tmp := bytes.NewBufferString("")

	_, err := tmp.WriteString(fmt.Sprintf("\n# profile.%s %s\n", p.Status, p.Name))
	if err != nil {
		return err
	}

	for _, ip := range p.IPList {
		route := p.Routes[ip]
		for _, host := range route.HostNames {
			prefix := ""
			if p.Status == Disabled {
				prefix = disabledPrefix
			}

			_, err = tmp.WriteString(fmt.Sprintf("%s%s %s\n", prefix, ip, host))
			if err != nil {
				return err
			}
		}
	}

	_, err = tmp.WriteString("# end\n")
	if err != nil {
		return err
	}

	// Write to input writer after knowing the profile is well-formed
	_, err = w.WriteString(tmp.String())

	return err
}

func uniqueStrings(xs []string) []string {
	list := []string{}

	keys := make(map[string]bool)

	for _, entry := range xs {
		if _, value := keys[entry]; !value {
			keys[entry] = true

			list = append(list, entry)
		}
	}

	return list
}

func remove(s []string, n string) []string {
	list := []string{}

	for _, x := range s {
		if x != n {
			list = append(list, x)
		}
	}

	return list
}
