package parser

import (
	"fmt"
	"strings"

	dtypes "github.com/docker/docker/api/types"

	"github.com/guumaster/hostctl/pkg/docker"
	"github.com/guumaster/hostctl/pkg/types"
)

// NewProfileFromDocker creates a new profile from docker info.
func NewProfileFromDocker(opts *docker.Options) (*types.Profile, error) {
	p := &types.Profile{}

	if err := validateDockerOptions(opts); err != nil {
		return nil, err
	}

	containers, err := docker.GetContainerList(opts)
	if err != nil {
		return nil, err
	}

	if err := addFromContainer(p, containers, opts); err != nil {
		return nil, err
	}

	return p, nil
}

// NewProfileFromDockerCompose creates a new profile from docker info.
func NewProfileFromDockerCompose(opts *docker.Options) (*types.Profile, error) {
	p := &types.Profile{}

	if err := validateDockerOptions(opts); err != nil {
		return nil, err
	}

	containers, err := docker.GetContainerList(opts)
	if err != nil {
		return nil, err
	}

	composeServices, err := docker.ParseComposeFile(opts.ComposeFile, opts.ProjectName)
	if err != nil {
		return nil, err
	}

	if err := addFromComposeService(p, containers, composeServices, opts); err != nil {
		return nil, err
	}

	return p, nil
}

// validateDockerOptions makes sure an attacker-controlled domain suffix
// cannot inject routes or profile blocks once concatenated to a container
// name. An empty domain keeps the historical behavior.
func validateDockerOptions(opts *docker.Options) error {
	if opts == nil {
		return types.ErrInvalidHostname
	}

	if opts.Domain == "" {
		return nil
	}

	if err := types.ValidateHostname(opts.Domain); err != nil {
		return fmt.Errorf("invalid docker domain suffix: %w", err)
	}

	return nil
}

func addFromContainer(profile *types.Profile, containers []dtypes.Container, opts *docker.Options) error {
	var routes []*types.Route

	for _, c := range containers {
		for _, n := range c.NetworkSettings.Networks {
			if opts.NetworkID != "" && n.NetworkID != opts.NetworkID {
				continue
			}

			name := strings.Replace(c.Names[0], "/", "", -1)

			name = fmt.Sprintf("%s.%s", name, opts.Domain)
			routes = append(routes, types.NewRoute(n.IPAddress, name))
		}
	}

	return profile.AddRoutes(routes)
}

func addFromComposeService(p *types.Profile, containers []dtypes.Container, srv []string, opts *docker.Options) error {
	for _, c := range containers {
		for _, n := range c.NetworkSettings.Networks {
			if opts.NetworkID != "" && n.NetworkID != opts.NetworkID {
				continue
			}

			name := strings.Replace(c.Names[0], "/", "", -1)

			routes := routeFromService(srv, name, n.IPAddress, opts)
			if len(routes) > 0 {
				if err := p.AddRoutes(routes); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func routeFromService(srv []string, name string, ip string, opts *docker.Options) []*types.Route {
	// removeSuffix := regexp.MustCompile("(_[0-9]+)$")
	routes := []*types.Route{}

	for _, s := range srv {
		if !strings.Contains(name, s) {
			continue
		}

		// name := removeSuffix.ReplaceAllString(name, "")
		if !opts.KeepPrefix {
			name = strings.Replace(name, opts.ProjectName+"_", "", 1)
		}

		name = fmt.Sprintf("%s.%s", name, opts.Domain)
		routes = append(routes, types.NewRoute(ip, name))
	}

	return routes
}
