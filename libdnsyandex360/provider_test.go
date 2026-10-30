package libdnsyandex360

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// fakeAPI is an in-memory implementation of the Yandex 360 DNS API.
type fakeAPI struct {
	mu      sync.Mutex
	nextID  int64
	records map[string][]apiRecord
	perPage int
}

func newFakeAPI(t *testing.T) (*fakeAPI, *Provider) {
	api := &fakeAPI{nextID: 1, records: map[string][]apiRecord{}, perPage: 2}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	return api, &Provider{OAuthToken: "token", OrgID: "42", BaseURL: srv.URL}
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.Header.Get("Authorization") != "OAuth token" {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 16, "message": "unauthenticated"})
		return
	}

	// /directory/v1/org/42/domains/{domain}/dns[/{id}]
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 7 || parts[3] != "42" || parts[6] != "dns" {
		http.NotFound(w, r)
		return
	}
	domain := parts[5]

	switch {
	case r.Method == http.MethodGet && len(parts) == 7:
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		all := f.records[domain]
		pages := (len(all) + f.perPage - 1) / f.perPage
		start := min((page-1)*f.perPage, len(all))
		end := min(start+f.perPage, len(all))
		_ = json.NewEncoder(w).Encode(listResponse{Records: all[start:end], Page: page, Pages: pages, PerPage: f.perPage, Total: len(all)})
	case r.Method == http.MethodPost && len(parts) == 7:
		var rec apiRecord
		_ = json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = f.nextID
		f.nextID++
		f.records[domain] = append(f.records[domain], rec)
		_ = json.NewEncoder(w).Encode(rec)
	case r.Method == http.MethodDelete && len(parts) == 8:
		id, _ := strconv.ParseInt(parts[7], 10, 64)
		recs := f.records[domain]
		for i, rec := range recs {
			if rec.ID == id {
				f.records[domain] = append(recs[:i], recs[i+1:]...)
				_, _ = w.Write([]byte("{}"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 5, "message": "not found"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestAppendGetDelete(t *testing.T) {
	api, p := newFakeAPI(t)
	ctx := context.Background()
	zone := "example.com."

	added, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token-1"},
		libdns.TXT{Name: "_acme-challenge.sub", TTL: 5 * time.Minute, Text: "token-2"},
		libdns.Address{Name: "@", TTL: time.Hour, IP: mustAddr(t, "192.0.2.1")},
		libdns.MX{Name: "@", TTL: time.Hour, Preference: 10, Target: "mx.example.com."},
		libdns.SRV{Service: "sip", Transport: "tcp", Name: "@", TTL: time.Hour, Priority: 1, Weight: 2, Port: 5060, Target: "sip.example.com."},
	})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if len(added) != 5 {
		t.Fatalf("added %d records, want 5", len(added))
	}
	if got := added[0].(libdns.TXT); got.TTL != DefaultTTL || got.ProviderData != int64(1) {
		t.Fatalf("added[0] = %+v", got)
	}

	sent := api.records["example.com"]
	if sent[0].Name != "_acme-challenge" || sent[0].Type != "TXT" || sent[0].Text != "token-1" || sent[0].TTL != 21600 {
		t.Fatalf("sent TXT = %+v", sent[0])
	}
	if sent[3].Exchange != "mx.example.com" || sent[3].Preference != 10 {
		t.Fatalf("sent MX = %+v", sent[3])
	}
	if sent[4].Name != "_sip._tcp" || sent[4].Port != 5060 || sent[4].Target != "sip.example.com" {
		t.Fatalf("sent SRV = %+v", sent[4])
	}

	got, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("GetRecords returned %d records (pagination?), want 5", len(got))
	}
	if srv, ok := got[4].(libdns.SRV); !ok || srv.Service != "sip" || srv.Transport != "tcp" || srv.Name != "@" {
		t.Fatalf("got SRV = %#v", got[4])
	}

	// Delete by value, as certmagic does; a non-matching value must survive.
	deleted, err := p.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token-1"},
		libdns.TXT{Name: "_acme-challenge.sub", Text: "other"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != 1 || deleted[0].(libdns.TXT).Text != "token-1" {
		t.Fatalf("deleted = %+v", deleted)
	}
	if n := len(api.records["example.com"]); n != 4 {
		t.Fatalf("%d records left, want 4", n)
	}

	// Wildcard delete by name and type.
	deleted, err = p.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: "_acme-challenge.sub", Type: "TXT"}})
	if err != nil || len(deleted) != 1 {
		t.Fatalf("wildcard delete = %+v, %v", deleted, err)
	}
}

func TestFullyQualifiedNamesFromAPI(t *testing.T) {
	api, p := newFakeAPI(t)
	api.records["example.com"] = []apiRecord{
		{ID: 7, Name: "_acme-challenge.example.com", Type: "TXT", Text: "v", TTL: 60},
		{ID: 8, Name: "example.com.", Type: "A", Address: "192.0.2.1", TTL: 60},
	}

	got, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if got[0].RR().Name != "_acme-challenge" || got[1].RR().Name != "@" {
		t.Fatalf("names = %q, %q", got[0].RR().Name, got[1].RR().Name)
	}

	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "v"}})
	if err != nil || len(deleted) != 1 {
		t.Fatalf("DeleteRecords = %+v, %v", deleted, err)
	}
}

func TestAPIError(t *testing.T) {
	_, p := newFakeAPI(t)
	p.OAuthToken = "wrong"

	_, err := p.GetRecords(context.Background(), "example.com.")
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.StatusCode != http.StatusUnauthorized || apiErr.Message != "unauthenticated" {
		t.Fatalf("err = %#v", err)
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, p := range []*Provider{
		{OrgID: "1"},
		{OAuthToken: "t"},
		{OAuthToken: "t", OrgID: "x"},
	} {
		if _, err := p.GetRecords(context.Background(), "example.com."); err == nil {
			t.Errorf("provider %+v: expected error", p)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
