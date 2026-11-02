package yandex360

import (
	"context"
	"errors"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"

	"github.com/unknown-gd/caddy-yandex360-dns/libdnsyandex360"
)

// Provider lets Caddy read and manipulate DNS records hosted by Yandex 360.
type Provider struct {
	*libdnsyandex360.Provider

	// PropagationTimeout is how long AppendRecords waits for created TXT
	// records to appear on the zone's authoritative nameservers.
	// Defaults to 600s; -1 disables the check.
	PropagationTimeout caddy.Duration `json:"propagation_timeout,omitempty"`
	// PollingInterval is the time between propagation checks. Defaults to 15s.
	PollingInterval caddy.Duration `json:"polling_interval,omitempty"`

	// checkTXT overrides the propagation check. Used in tests.
	checkTXT func(ctx context.Context, zone, fqdn, value string) (bool, error)
}

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.yandex360",
		New: func() caddy.Module { return &Provider{Provider: new(libdnsyandex360.Provider)} },
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (p *Provider) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()
	p.OAuthToken = repl.ReplaceAll(p.OAuthToken, "")
	p.OrgID = repl.ReplaceAll(p.OrgID, "")

	if p.OAuthToken == "" {
		return errors.New("missing Yandex 360 OAuth token: set oauth_token")
	}
	if p.OrgID == "" {
		return errors.New("missing Yandex 360 organization ID: set org_id")
	}
	if id, err := strconv.ParseInt(p.OrgID, 10, 64); err != nil || id <= 0 {
		return errors.New("invalid org_id: must be a positive integer")
	}

	if p.PropagationTimeout == 0 {
		p.PropagationTimeout = caddy.Duration(DefaultPropagationTimeout)
	}
	if p.PollingInterval == 0 {
		p.PollingInterval = caddy.Duration(DefaultPollingInterval)
	}
	if p.PollingInterval < 0 {
		return errors.New("polling_interval must be positive")
	}
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	yandex360 [<oauth_token> <org_id>] {
//	    oauth_token <token>
//	    org_id <id>
//	    propagation_timeout <duration>  # default 600s, -1 disables
//	    polling_interval <duration>     # default 15s
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 0:
		case 2:
			p.OAuthToken, p.OrgID = args[0], args[1]
		default:
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "oauth_token":
				if !d.AllArgs(&p.OAuthToken) {
					return d.ArgErr()
				}
			case "org_id":
				if !d.AllArgs(&p.OrgID) {
					return d.ArgErr()
				}
			case "propagation_timeout", "polling_interval":
				name := d.Val()
				var value string
				if !d.AllArgs(&value) {
					return d.ArgErr()
				}
				dur := caddy.Duration(-1)
				if value != "-1" {
					parsed, err := caddy.ParseDuration(value)
					if err != nil {
						return d.Errf("invalid %s %q: %v", name, value, err)
					}
					dur = caddy.Duration(parsed)
				}
				if name == "propagation_timeout" {
					p.PropagationTimeout = dur
				} else {
					p.PollingInterval = dur
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
)
