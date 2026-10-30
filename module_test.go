package yandex360

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/caddy-dns/yandex360/libdnsyandex360"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		token string
		orgID string
	}{
		{
			name: "block",
			input: `yandex360 {
				oauth_token token
				org_id 123
			}`,
			token: "token",
			orgID: "123",
		},
		{
			name:  "inline",
			input: "yandex360 token 123",
			token: "token",
			orgID: "123",
		},
		{
			name:  "placeholders",
			input: "yandex360 {env.YANDEX360_OAUTH_TOKEN} {env.YANDEX360_ORG_ID}",
			token: "{env.YANDEX360_OAUTH_TOKEN}",
			orgID: "{env.YANDEX360_ORG_ID}",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := newProvider(libdnsyandex360.Provider{})
			if err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(test.input)); err != nil {
				t.Fatalf("UnmarshalCaddyfile failed: %v", err)
			}
			if p.OAuthToken != test.token || p.OrgID != test.orgID {
				t.Fatalf("provider = {OAuthToken:%q OrgID:%q}", p.OAuthToken, p.OrgID)
			}
		})
	}
}

func TestUnmarshalCaddyfileDurations(t *testing.T) {
	p := newProvider(libdnsyandex360.Provider{})
	err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`yandex360 token 123 {
		propagation_timeout 5m
		polling_interval 30s
	}`))
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}
	if p.PropagationTimeout != caddy.Duration(5*time.Minute) || p.PollingInterval != caddy.Duration(30*time.Second) {
		t.Fatalf("provider = {PropagationTimeout:%v PollingInterval:%v}", p.PropagationTimeout, p.PollingInterval)
	}

	p = newProvider(libdnsyandex360.Provider{})
	if err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser("yandex360 { \n propagation_timeout -1 \n }")); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}
	if p.PropagationTimeout != -1 {
		t.Fatalf("PropagationTimeout = %v, want -1", p.PropagationTimeout)
	}
}

func TestProvisionDefaults(t *testing.T) {
	p := newProvider(libdnsyandex360.Provider{OAuthToken: "token", OrgID: "123"})
	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if p.PropagationTimeout != caddy.Duration(600*time.Second) || p.PollingInterval != caddy.Duration(15*time.Second) {
		t.Fatalf("provider = {PropagationTimeout:%v PollingInterval:%v}", p.PropagationTimeout, p.PollingInterval)
	}
}

func TestUnmarshalCaddyfileRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single positional argument",
			input: "yandex360 token",
			want:  "wrong argument count",
		},
		{
			name: "unknown directive",
			input: `yandex360 {
				api_token token
			}`,
			want: "unrecognized subdirective",
		},
		{
			name: "missing oauth token",
			input: `yandex360 {
				oauth_token
			}`,
			want: "wrong argument count",
		},
		{
			name: "missing org id",
			input: `yandex360 {
				org_id
			}`,
			want: "wrong argument count",
		},
		{
			name: "invalid duration",
			input: `yandex360 {
				polling_interval soon
			}`,
			want: "invalid polling_interval",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := newProvider(libdnsyandex360.Provider{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser(test.input))
			checkErr(t, err, test.want)
		})
	}
}

func TestProvisionValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  libdnsyandex360.Provider
		wantErr string
	}{
		{
			name:    "missing token",
			config:  libdnsyandex360.Provider{OrgID: "123"},
			wantErr: "set oauth_token",
		},
		{
			name:    "missing org id",
			config:  libdnsyandex360.Provider{OAuthToken: "token"},
			wantErr: "set org_id",
		},
		{
			name:    "invalid org id",
			config:  libdnsyandex360.Provider{OAuthToken: "token", OrgID: "abc"},
			wantErr: "invalid org_id",
		},
		{
			name:   "valid",
			config: libdnsyandex360.Provider{OAuthToken: "token", OrgID: "123"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := newProvider(test.config).Provision(caddy.Context{})
			checkErr(t, err, test.wantErr)
		})
	}
}

func TestProvisionReplacesPlaceholders(t *testing.T) {
	t.Setenv("Y360_TEST_OAUTH_TOKEN", "token")
	t.Setenv("Y360_TEST_ORG_ID", "123")

	p := newProvider(libdnsyandex360.Provider{
		OAuthToken: "{env.Y360_TEST_OAUTH_TOKEN}",
		OrgID:      "{env.Y360_TEST_ORG_ID}",
	})

	if err := p.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if p.OAuthToken != "token" || p.OrgID != "123" {
		t.Fatalf("provider = {OAuthToken:%q OrgID:%q}", p.OAuthToken, p.OrgID)
	}
}

func newProvider(config libdnsyandex360.Provider) *Provider {
	return &Provider{Provider: &config}
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("got error %q, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("got nil error, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}
