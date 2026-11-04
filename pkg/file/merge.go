package file

import (
	"github.com/guumaster/hostctl/pkg/types"
)

// MergeFile joins new content with existing content.
func (f *File) MergeFile(from *File) error {
	ps := make([]*types.Profile, len(from.data.ProfileNames))
	for i, name := range from.data.ProfileNames {
		ps[i] = from.data.Profiles[name]
	}

	return f.MergeProfiles(ps)
}

// MergeProfiles joins new profiles with existing content. The whole batch is
// validated before any state change, so an invalid profile cannot be merged
// partially.
func (f *File) MergeProfiles(profiles []*types.Profile) error {
	for _, newP := range profiles {
		if err := newP.Validate(); err != nil {
			return err
		}
	}

	for _, newP := range profiles {
		newName := newP.Name

		_, ok := f.data.Profiles[newName]
		if !ok {
			f.data.ProfileNames = append(f.data.ProfileNames, newName)
			f.data.Profiles[newName] = newP

			continue
		}

		baseP := f.data.Profiles[newName]

		var routes []*types.Route
		for _, r := range newP.Routes {
			routes = append(routes, r)
		}

		if err := baseP.AddRoutes(routes); err != nil {
			return err
		}

		f.data.Profiles[newName] = baseP
	}

	return nil
}
