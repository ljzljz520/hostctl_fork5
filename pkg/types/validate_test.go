package types

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateHostname(t *testing.T) {
	valid := []string{
		"localhost",
		"myrouter", // single-label local name
		"loc",
		"nas.local",
		"a-b_c.io",
		"container_1.lan",
		"service.foo-bar.local",
		"xn--fa-hia.de",
		"UPPER.Case",
	}

	for _, h := range valid {
		t.Run("valid/"+h, func(t *testing.T) {
			assert.NoError(t, ValidateHostname(h))
		})
	}

	invalid := map[string]string{
		"empty":                              "",
		"newline route injection":            "evil.com\n6.6.6.6 pwned.loc",
		"carriage return":                    "evil.com\rpwned",
		"tab field separator":                "evil.com\tpwned",
		"space field separator":              "evil.com pwned",
		"comment marker":                     "evil.com#pwned",
		"null byte":                          "evil.com\x00pwned",
		"forged enabled block":               "x\n# profile.on forged\n6.6.6.6 pwned.loc",
		"forged block end":                   "evil.loc\n# end",
		"disabled escape with carriage":      "evil.loc\r6.6.6.6 pwned.loc",
		"vertical tab control":               "evil.com\vpwned",
		"leading newline":                    "\nevil.com",
		"forged disabled then enabled route": "# off\n6.6.6.6 pwned.loc",
	}

	for name, h := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			assert.ErrorIs(t, ValidateHostname(h), ErrInvalidHostname)
		})
	}
}

func TestValidateProfileName(t *testing.T) {
	valid := []string{
		"profile1",
		"my profile", // existing profiles may contain spaces
		"my profile ",
		"a.b-c_x",
	}

	for _, name := range valid {
		t.Run("valid/"+name, func(t *testing.T) {
			assert.NoError(t, ValidateProfileName(name))
		})
	}

	invalid := map[string]string{
		"empty":                    "",
		"whitespace only":          "   ",
		"newline header injection": "evil\n# profile.on forged",
		"forged enabled block":     "evil\n# profile.on forged\n6.6.6.6 pwned.loc\n# end",
		"carriage return":          "evil\rf",
		"tab":                      "evil\tf",
		"comment marker":           "evil # profile.on",
		"disabled escape":          "x\n# profile.on escape",
		"control char":             "evil\x00f",
	}

	for name, n := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			assert.ErrorIs(t, ValidateProfileName(n), ErrInvalidProfileName)
		})
	}
}

func TestValidateRoute(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, ValidateRoute(NewRoute("127.0.0.1", "a.loc", "b.loc")))
		assert.NoError(t, ValidateRoute(NewRoute("::1", "localhost")))
	})

	t.Run("nil route", func(t *testing.T) {
		assert.ErrorIs(t, ValidateRoute(nil), ErrInvalidIP)
	})

	t.Run("nil ip", func(t *testing.T) {
		r := NewRoute("not-an-ip", "a.loc")
		assert.Nil(t, r.IP)
		assert.ErrorIs(t, ValidateRoute(r), ErrInvalidIP)
	})

	t.Run("malicious hostname", func(t *testing.T) {
		r := NewRoute("1.2.3.4", "good.loc", "evil.com\n6.6.6.6 pwned.loc")
		assert.ErrorIs(t, ValidateRoute(r), ErrInvalidHostname)
	})
}

func TestProfileValidate(t *testing.T) {
	t.Run("valid profile", func(t *testing.T) {
		p := &Profile{Name: "p", Status: Enabled}
		assert.NoError(t, p.AddRoute(NewRoute("1.1.1.1", "a.loc")))
		assert.NoError(t, p.Validate())
	})

	t.Run("empty status is accepted", func(t *testing.T) {
		p := &Profile{Name: "p"}
		assert.NoError(t, p.AddRoute(NewRoute("1.1.1.1", "a.loc")))
		assert.NoError(t, p.Validate())
	})

	t.Run("malicious status is rejected", func(t *testing.T) {
		p := &Profile{
			Name:   "p",
			Status: Status("off\n# profile.on escaped\n6.6.6.6 pwned.loc"),
		}
		assert.NoError(t, p.AddRoute(NewRoute("1.1.1.1", "a.loc")))
		assert.ErrorIs(t, p.Validate(), ErrInvalidStatus)
	})

	t.Run("malicious name is rejected", func(t *testing.T) {
		p := &Profile{Name: "p\n# profile.on forged", Status: Enabled}
		assert.NoError(t, p.AddRoute(NewRoute("1.1.1.1", "a.loc")))
		assert.ErrorIs(t, p.Validate(), ErrInvalidProfileName)
	})
}

func TestAddRoutesRejectsBatchAtomically(t *testing.T) {
	t.Run("invalid route anywhere rejects the whole batch", func(t *testing.T) {
		batches := [][]*Route{
			{
				NewRoute("1.1.1.1", "good.loc"),
				NewRoute("2.2.2.2", "evil.com\n6.6.6.6 pwned.loc"),
			},
			{
				NewRoute("2.2.2.2", "evil.com\n6.6.6.6 pwned.loc"),
				NewRoute("1.1.1.1", "good.loc"),
			},
		}

		for _, routes := range batches {
			p := &Profile{}

			err := p.AddRoutes(routes)
			assert.Error(t, err)
			assert.Empty(t, p.Routes)
			assert.Empty(t, p.IPList)
		}
	})

	t.Run("failed batch never mutates existing routes", func(t *testing.T) {
		p := &Profile{}
		assert.NoError(t, p.AddRoute(NewRoute("1.1.1.1", "keep.loc")))

		err := p.AddRoutes([]*Route{
			NewRoute("2.2.2.2", "new.loc"),
			NewRoute("3.3.3.3", "evil\n6.6.6.6 pwned.loc"),
		})
		assert.Error(t, err)

		names, err := p.GetHostNames("1.1.1.1")
		assert.NoError(t, err)
		assert.Equal(t, []string{"keep.loc"}, names)

		_, err = p.GetHostNames("2.2.2.2")
		assert.Error(t, err)
	})
}

func TestRenderRejectsInjection(t *testing.T) {
	t.Run("malicious hostname added by struct manipulation", func(t *testing.T) {
		p := &Profile{
			Name:   "victim",
			Status: Disabled,
			Routes: map[string]*Route{
				"6.6.6.6": {
					IP:        net.ParseIP("6.6.6.6"),
					HostNames: []string{"evil.loc\n# profile.on escaped\n6.6.6.6 pwned.loc"},
				},
			},
			IPList: []string{"6.6.6.6"},
		}

		b := bytes.NewBufferString("")
		err := p.Render(b)
		assert.Error(t, err)
		assert.Empty(t, b.String())
	})

	t.Run("malicious profile name", func(t *testing.T) {
		p := &Profile{
			Name:   "victim\n# profile.on escaped",
			Status: Disabled,
			Routes: map[string]*Route{
				"1.1.1.1": {IP: net.ParseIP("1.1.1.1"), HostNames: []string{"a.loc"}},
			},
			IPList: []string{"1.1.1.1"},
		}

		b := bytes.NewBufferString("")
		err := p.Render(b)
		assert.Error(t, err)
		assert.Empty(t, b.String())
	})

	t.Run("spaced profile name still renders", func(t *testing.T) {
		p := &Profile{Name: "my profile", Status: Enabled}
		assert.NoError(t, p.AddRoute(NewRoute("1.1.1.1", "myrouter")))

		b := bytes.NewBufferString("")
		assert.NoError(t, p.Render(b))
		assert.True(t, strings.Contains(b.String(), "# profile.on my profile"))
		assert.True(t, strings.Contains(b.String(), "1.1.1.1 myrouter"))
	})
}

func TestDefaultProfileRenderRejectsInjection(t *testing.T) {
	t.Run("comment with line break", func(t *testing.T) {
		d := DefaultProfile{
			{Comment: "# innocent\n6.6.6.6 pwned.loc"},
		}

		b := bytes.NewBufferString("")
		err := d.Render(b)
		assert.ErrorIs(t, err, ErrInvalidRow)
		assert.Empty(t, b.String())
	})

	t.Run("valid rows render", func(t *testing.T) {
		d := DefaultProfile{
			{Comment: "# a comment"},
			{IP: "127.0.0.1", Host: "localhost"},
			{},
		}

		b := bytes.NewBufferString("")
		assert.NoError(t, d.Render(b))
		assert.Contains(t, b.String(), "# a comment")
		assert.Contains(t, b.String(), "127.0.0.1 localhost")
	})
}
