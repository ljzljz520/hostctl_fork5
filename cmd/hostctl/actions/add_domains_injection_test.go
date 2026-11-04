package actions

import (
	"os"
	"testing"

	as "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddDomainsInjection covers the CLI entry point with arguments an
// automated caller could pass: the command must fail and the hosts file must
// remain byte-for-byte identical.
func TestAddDomainsInjection(t *testing.T) {
	cases := map[string][]string{
		"hostname with forged enabled block": {
			"add", "domains", "profile2",
			"evil.loc\n# profile.on escaped\n6.6.6.6 pwned.loc",
			"--quiet",
		},
		"profile name injection": {
			"add", "domains", "evil\n# profile.on escaped",
			"evil.loc",
			"--quiet",
		},
		"hostname containing a tab": {
			"add", "domains", "profile1",
			"evil.loc\tpwned.loc",
			"--quiet",
		},
	}

	for name, extraArgs := range cases {
		t.Run(name, func(t *testing.T) {
			hostFile, err := os.CreateTemp("/tmp", "hostctl_injection_")
			require.NoError(t, err)

			defer func() {
				_ = hostFile.Close()
				_ = os.Remove(hostFile.Name())
			}()

			fixture := []byte(`
127.0.0.1 localhost

# profile.on profile1
127.0.0.1 first.loc
# end

# profile.off profile2
# 127.0.0.1 first.loc
# end
`)
			_, err = hostFile.Write(fixture)
			require.NoError(t, err)
			require.NoError(t, hostFile.Close())

			cmd := NewRootCmd()
			args := append(extraArgs, "--host-file", hostFile.Name())
			cmd.SetArgs(args)

			require.Error(t, cmd.Execute())

			raw, err := os.ReadFile(hostFile.Name())
			require.NoError(t, err)
			as.Equal(t, string(fixture), string(raw))
		})
	}
}
