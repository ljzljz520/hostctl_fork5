package file

import (
	"errors"

	"github.com/guumaster/hostctl/pkg/types"
)

// ReplaceProfile removes previous profile with same name and add new profile to the list.
// The new profile is fully validated before the previous one is removed, so an
// invalid replacement leaves the existing profile untouched.
func (f *File) ReplaceProfile(p *types.Profile) error {
	if p.Name == types.Default {
		return types.ErrDefaultProfile
	}

	if err := p.Validate(); err != nil {
		return err
	}

	err := f.RemoveProfile(p.Name)
	if err != nil && !errors.Is(err, types.ErrUnknownProfile) {
		return err
	}

	return f.AddProfile(p)
}
