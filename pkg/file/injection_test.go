package file

import (
	"net"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guumaster/hostctl/pkg/parser"
	"github.com/guumaster/hostctl/pkg/types"
)

// payload tries to close the disabled block, forge an enabled profile and
// inject an extra route.
const injectionHost = "evil.loc\n# profile.on escaped\n6.6.6.6 pwned.loc\n# end"

func reloadAndParse(t *testing.T, mem afero.Fs, path string) *types.Content {
	t.Helper()

	raw, err := afero.ReadFile(mem, path)
	require.NoError(t, err)

	data, err := parser.Parse(strings.NewReader(string(raw)))
	require.NoError(t, err)

	return data
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func readString(t *testing.T, mem afero.Fs, path string) string {
	t.Helper()

	raw, err := afero.ReadFile(mem, path)
	require.NoError(t, err)

	return string(raw)
}

func TestAddRouteStructuralInjection(t *testing.T) {
	// baseline is the serialized pristine state (a flush normalizes
	// whitespace, so compare against a clean flush rather than the fixture).
	baseMem := createBasicFS(t)
	base, err := NewWithFs("/tmp/etc/hosts", baseMem)
	require.NoError(t, err)
	require.NoError(t, base.Flush())
	base.Close()
	baseline := readString(t, baseMem, "/tmp/etc/hosts")

	t.Run("hostname injection into disabled profile is rejected", func(t *testing.T) {
		mem := createBasicFS(t)

		f, err := NewWithFs("/tmp/etc/hosts", mem)
		require.NoError(t, err)

		err = f.AddRoute("profile2", types.NewRoute("5.5.5.5", injectionHost))
		assert.ErrorIs(t, err, types.ErrInvalidHostname)

		// In-memory state keeps its original shape.
		p, err := f.GetProfile("profile2")
		require.NoError(t, err)
		assert.Equal(t, types.Disabled, p.Status)
		assert.Equal(t, []string{"first.loc", "second.loc"}, p.GetAllHostNames())
		_, err = f.GetProfile("escaped")
		assert.ErrorIs(t, err, types.ErrUnknownProfile)

		// A later flush serializes only the untouched state.
		require.NoError(t, f.Flush())
		f.Close()

		after := readString(t, mem, "/tmp/etc/hosts")
		assert.Equal(t, baseline, after)

		data := reloadAndParse(t, mem, "/tmp/etc/hosts")
		assert.Equal(t, []string{"profile1", "profile2"}, data.ProfileNames)
		assert.Equal(t, types.Disabled, data.Profiles["profile2"].Status)
		assert.NotContains(t, after, "pwned.loc")
		assert.NotContains(t, after, "6.6.6.6")
		assert.NotContains(t, after, "# profile.on escaped")
	})

	t.Run("mixed batch fails atomically", func(t *testing.T) {
		mem := createBasicFS(t)

		f, err := NewWithFs("/tmp/etc/hosts", mem)
		require.NoError(t, err)

		err = f.AddRoutes("fresh", []*types.Route{
			types.NewRoute("5.5.5.5", "good.loc"),
			types.NewRoute("5.5.5.5", "bad.loc\n6.6.6.6 pwned.loc"),
		})
		assert.ErrorIs(t, err, types.ErrInvalidHostname)

		// Neither the valid route nor the new profile survive.
		_, err = f.GetProfile("fresh")
		assert.ErrorIs(t, err, types.ErrUnknownProfile)

		require.NoError(t, f.Flush())
		f.Close()

		after := readString(t, mem, "/tmp/etc/hosts")
		assert.Equal(t, baseline, after)
		assert.NotContains(t, after, "good.loc")
		assert.NotContains(t, after, "pwned.loc")
	})

	t.Run("profile name injection is rejected", func(t *testing.T) {
		mem := createBasicFS(t)

		f, err := NewWithFs("/tmp/etc/hosts", mem)
		require.NoError(t, err)

		name := "evil\n# profile.on escaped\n6.6.6.6 pwned.loc"
		err = f.AddRoute(name, types.NewRoute("5.5.5.5", "a.loc"))
		assert.ErrorIs(t, err, types.ErrInvalidProfileName)

		_, err = f.GetProfile("escaped")
		assert.ErrorIs(t, err, types.ErrUnknownProfile)

		require.NoError(t, f.Flush())
		f.Close()

		raw := readString(t, mem, "/tmp/etc/hosts")
		assert.NotContains(t, raw, "escaped")
		assert.NotContains(t, raw, "6.6.6.6")
	})

	t.Run("invalid ip is rejected before mutation", func(t *testing.T) {
		mem := createBasicFS(t)

		f, err := NewWithFs("/tmp/etc/hosts", mem)
		require.NoError(t, err)

		err = f.AddRoute("profile1", types.NewRoute("not-an-ip", "a.loc"))
		assert.ErrorIs(t, err, types.ErrInvalidIP)

		p, err := f.GetProfile("profile1")
		require.NoError(t, err)
		assert.Equal(t, []string{"first.loc", "second.loc"}, p.GetAllHostNames())
	})
}

func TestReplaceProfileKeepsPreviousOnInvalidInput(t *testing.T) {
	mem := createBasicFS(t)

	f, err := NewWithFs("/tmp/etc/hosts", mem)
	require.NoError(t, err)

	malicious := &types.Profile{
		Name:   "profile1",
		Status: types.Enabled,
		Routes: map[string]*types.Route{
			"6.6.6.6": {
				IP:        parseIP("6.6.6.6"),
				HostNames: []string{"evil.loc\n# profile.on escaped"},
			},
		},
		IPList: []string{"6.6.6.6"},
	}

	err = f.ReplaceProfile(malicious)
	assert.ErrorIs(t, err, types.ErrInvalidHostname)

	// The pre-existing profile is still there, untouched.
	p, err := f.GetProfile("profile1")
	require.NoError(t, err)
	assert.Equal(t, types.Enabled, p.Status)
	assert.Equal(t, []string{"first.loc", "second.loc"}, p.GetAllHostNames())

	require.NoError(t, f.Flush())
	f.Close()

	data := reloadAndParse(t, mem, "/tmp/etc/hosts")
	require.Contains(t, data.Profiles, "profile1")
	assert.Equal(t, types.Enabled, data.Profiles["profile1"].Status)
	assert.Equal(t, []string{"first.loc", "second.loc"},
		data.Profiles["profile1"].GetAllHostNames())

	raw := readString(t, mem, "/tmp/etc/hosts")
	assert.NotContains(t, raw, "escaped")
}

func TestMergeProfilesRejectsBatchAtomically(t *testing.T) {
	mem := createBasicFS(t)

	f, err := NewWithFs("/tmp/etc/hosts", mem)
	require.NoError(t, err)

	profiles := []*types.Profile{
		{
			Name:   "newone",
			Status: types.Enabled,
			Routes: map[string]*types.Route{
				"5.5.5.5": {IP: parseIP("5.5.5.5"), HostNames: []string{"good.loc"}},
			},
			IPList: []string{"5.5.5.5"},
		},
		{
			Name:   "evil\n# profile.on escaped",
			Status: types.Enabled,
			Routes: map[string]*types.Route{
				"6.6.6.6": {IP: parseIP("6.6.6.6"), HostNames: []string{"pwned.loc"}},
			},
			IPList: []string{"6.6.6.6"},
		},
	}

	err = f.MergeProfiles(profiles)
	assert.Error(t, err)

	// The valid first profile must not have been merged either.
	_, err = f.GetProfile("newone")
	assert.ErrorIs(t, err, types.ErrUnknownProfile)
	_, err = f.GetProfile("escaped")
	assert.ErrorIs(t, err, types.ErrUnknownProfile)
	assert.Equal(t, []string{"profile1", "profile2"}, f.GetProfileNames())
}

func TestValidLocalDomainsAndSpacedProfileName(t *testing.T) {
	mem := createBasicFS(t)

	f, err := NewWithFs("/tmp/etc/hosts", mem)
	require.NoError(t, err)

	// Single-label local names, underscores (docker style) and spaced
	// profile names must keep working.
	err = f.AddRoutes("my profile", []*types.Route{
		types.NewRoute("10.0.0.1", "myrouter", "nas.local", "container_1.lan"),
	})
	require.NoError(t, err)

	// Adding to a disabled profile keeps it disabled.
	err = f.AddRoute("profile2", types.NewRoute("10.0.0.2", "printer"))
	require.NoError(t, err)

	require.NoError(t, f.Flush())
	f.Close()

	// Serialize -> re-read: prove input only lands in the expected profile.
	data := reloadAndParse(t, mem, "/tmp/etc/hosts")

	assert.Equal(t, []string{"profile1", "profile2", "my profile"}, data.ProfileNames)

	spaced := data.Profiles["my profile"]
	require.NotNil(t, spaced)
	assert.Equal(t, types.Enabled, spaced.Status)
	names, err := spaced.GetHostNames("10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, []string{"myrouter", "nas.local", "container_1.lan"}, names)

	// The disabled profile stays disabled and all its lines remain comments.
	p2 := data.Profiles["profile2"]
	require.NotNil(t, p2)
	assert.Equal(t, types.Disabled, p2.Status)
	assert.Equal(t, []string{"first.loc", "second.loc", "printer"}, p2.GetAllHostNames())

	raw := readString(t, mem, "/tmp/etc/hosts")
	assert.Contains(t, raw, "# profile.off profile2\n# 127.0.0.1 first.loc")
	assert.Contains(t, raw, "# 10.0.0.2 printer")
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "6.6.6.6") || strings.Contains(line, "pwned") {
			t.Fatalf("unexpected injected line: %q", line)
		}
	}
}

func TestSerializedInputLandsOnlyInTargetProfile(t *testing.T) {
	mem := createBasicFS(t)

	f, err := NewWithFs("/tmp/etc/hosts", mem)
	require.NoError(t, err)

	err = f.AddRoute("profile1", types.NewRoute("9.9.9.9", "only.here.loc"))
	require.NoError(t, err)

	require.NoError(t, f.Flush())
	f.Close()

	data := reloadAndParse(t, mem, "/tmp/etc/hosts")

	count := 0

	for name, p := range data.Profiles {
		for _, ip := range p.IPList {
			hosts, err := p.GetHostNames(ip)
			require.NoError(t, err)

			for _, h := range hosts {
				if h == "only.here.loc" {
					count++
					assert.Equal(t, "profile1", name)
					assert.Equal(t, "9.9.9.9", ip)
				}
			}
		}
	}

	assert.Equal(t, 1, count, "hostname must appear exactly once, in profile1 only")
}
