package file

import (
	"github.com/guumaster/hostctl/pkg/types"
)

// AddProfile adds a profile to the list. The profile is validated before any
// state change so unsafe names or routes cannot reach the hosts file.
func (f *File) AddProfile(p *types.Profile) error {
	if p.Name == types.Default {
		return types.ErrDefaultProfile
	}

	if err := p.Validate(); err != nil {
		return err
	}

	return f.MergeProfiles([]*types.Profile{p})
}
