package yandex360

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/caddy-dns/yandex360/libdnsyandex360"
)

func newWaitingProvider(t *testing.T, check func(ctx context.Context, zone, fqdn, value string) (bool, error)) *Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"recordId": 1, "name": "_acme-challenge", "type": "TXT", "text": "v", "ttl": 60}`))
	}))
	t.Cleanup(srv.Close)

	return &Provider{
		Provider:           &libdnsyandex360.Provider{OAuthToken: "token", OrgID: "1", BaseURL: srv.URL},
		PropagationTimeout: caddy.Duration(50 * time.Millisecond),
		PollingInterval:    caddy.Duration(5 * time.Millisecond),
		checkTXT:           check,
	}
}

func appendChallenge(p *Provider) error {
	_, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "v"}})
	return err
}

func TestAppendRecordsWaitsForPropagation(t *testing.T) {
	calls := 0
	p := newWaitingProvider(t, func(_ context.Context, zone, fqdn, value string) (bool, error) {
		if zone != "example.com." || fqdn != "_acme-challenge.example.com." || value != "v" {
			t.Errorf("check(%q, %q, %q)", zone, fqdn, value)
		}
		calls++
		return calls == 3, nil
	})

	if err := appendChallenge(p); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if calls != 3 {
		t.Fatalf("checked %d times, want 3", calls)
	}
}

func TestAppendRecordsPropagationTimeout(t *testing.T) {
	p := newWaitingProvider(t, func(context.Context, string, string, string) (bool, error) {
		return false, errors.New("ns1 does not serve the record yet")
	})

	err := appendChallenge(p)
	if err == nil || !strings.Contains(err.Error(), "did not propagate") || !strings.Contains(err.Error(), "ns1") {
		t.Fatalf("err = %v", err)
	}
}

func TestAppendRecordsPropagationDisabled(t *testing.T) {
	p := newWaitingProvider(t, func(context.Context, string, string, string) (bool, error) {
		t.Error("propagation check must not run")
		return false, nil
	})
	p.PropagationTimeout = -1

	if err := appendChallenge(p); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
}

func TestHasTXTIgnoresCNAME(t *testing.T) {
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeCNAME}, Target: "other.example.net."},
		&dns.TXT{Hdr: dns.RR_Header{Name: "other.example.net.", Rrtype: dns.TypeTXT}, Txt: []string{"v"}},
	}
	if hasTXT(resp, "_acme-challenge.example.com", "v") {
		t.Fatal("TXT behind a CNAME must not count as propagated")
	}

	resp.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeTXT}, Txt: []string{"a", "b"}}}
	if !hasTXT(resp, "_acme-challenge.example.com", "ab") {
		t.Fatal("split TXT strings must be joined")
	}
}
