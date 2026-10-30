package yandex360

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// Defaults for the plugin's own propagation check. Yandex 360 DNS can be slow
// to propagate, so these are much more generous than Caddy's built-in check
// (2 minute timeout, 2 second interval).
const (
	DefaultPropagationTimeout = 600 * time.Second
	DefaultPollingInterval    = 15 * time.Second
)

// AppendRecords adds records to the zone, then waits until every added TXT
// record is served by all authoritative nameservers of the zone.
//
// The check queries the exact record name and never follows CNAMEs, so a
// wildcard CNAME covering _acme-challenge can't send it to another zone.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	added, err := p.Provider.AppendRecords(ctx, zone, recs)
	if err != nil || p.PropagationTimeout < 0 {
		return added, err
	}

	for _, rec := range added {
		rr := rec.RR()
		if rr.Type != "TXT" {
			continue
		}
		if err := p.waitForTXT(ctx, zone, libdns.AbsoluteName(rr.Name, zone), rr.Data); err != nil {
			return added, err
		}
	}
	return added, nil
}

func (p *Provider) waitForTXT(ctx context.Context, zone, fqdn, value string) error {
	check := p.checkTXT
	if check == nil {
		check = checkAuthoritativeTXT
	}

	timeout := time.Duration(p.PropagationTimeout)
	interval := time.Duration(p.PollingInterval)
	deadline := time.Now().Add(timeout)

	var lastErr error
	for {
		ready, err := check(ctx, zone, fqdn, value)
		if ready {
			return nil
		}
		lastErr = err
		if time.Now().Add(interval).After(deadline) {
			break
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if lastErr != nil {
		return fmt.Errorf("yandex360: TXT record %s did not propagate within %s: %w", fqdn, timeout, lastErr)
	}
	return fmt.Errorf("yandex360: TXT record %s did not propagate within %s", fqdn, timeout)
}

// checkAuthoritativeTXT reports whether every authoritative nameserver of the
// zone serves a TXT record with the given value at exactly fqdn.
func checkAuthoritativeTXT(ctx context.Context, zone, fqdn, value string) (bool, error) {
	nameservers, err := net.DefaultResolver.LookupNS(ctx, strings.TrimSuffix(zone, "."))
	if err != nil {
		return false, fmt.Errorf("looking up nameservers of %s: %w", zone, err)
	}
	if len(nameservers) == 0 {
		return false, fmt.Errorf("no nameservers found for %s", zone)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	msg.RecursionDesired = false

	client := &dns.Client{Timeout: 10 * time.Second}
	for _, ns := range nameservers {
		resp, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(strings.TrimSuffix(ns.Host, "."), "53"))
		if err != nil {
			return false, fmt.Errorf("querying %s: %w", ns.Host, err)
		}
		if !hasTXT(resp, fqdn, value) {
			return false, fmt.Errorf("%s does not serve the record yet", ns.Host)
		}
	}
	return true, nil
}

func hasTXT(resp *dns.Msg, fqdn, value string) bool {
	if resp.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if ok && strings.EqualFold(txt.Hdr.Name, dns.Fqdn(fqdn)) && strings.Join(txt.Txt, "") == value {
			return true
		}
	}
	return false
}
