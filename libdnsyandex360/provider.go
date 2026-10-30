// Package libdnsyandex360 implements a libdns provider for Yandex 360 DNS
// (https://360.yandex.ru), using the Yandex 360 Directory API.
package libdnsyandex360

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// DefaultTTL is used for records created without an explicit TTL.
const DefaultTTL = 6 * time.Hour

// Provider manages DNS records of domains connected to a Yandex 360 organization.
type Provider struct {
	// OAuthToken is a Yandex OAuth token with the directory:manage_dns scope.
	OAuthToken string `json:"oauth_token,omitempty"`
	// OrgID is the Yandex 360 organization ID.
	OrgID string `json:"org_id,omitempty"`

	// HTTPClient is used for API requests. Defaults to a client with a 30s timeout.
	HTTPClient *http.Client `json:"-"`
	// BaseURL overrides the API base URL. Intended for tests.
	BaseURL string `json:"-"`
}

func (p *Provider) client() (*client, error) {
	if p.OAuthToken == "" {
		return nil, errors.New("yandex360: oauth_token is required")
	}
	orgID, err := strconv.ParseInt(p.OrgID, 10, 64)
	if err != nil || orgID <= 0 {
		return nil, fmt.Errorf("yandex360: invalid org_id %q", p.OrgID)
	}

	rawBaseURL := p.BaseURL
	if rawBaseURL == "" {
		rawBaseURL = defaultBaseURL
	}
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil {
		return nil, fmt.Errorf("yandex360: invalid base URL: %w", err)
	}

	httpClient := p.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &client{token: p.OAuthToken, orgID: orgID, baseURL: baseURL, httpClient: httpClient}, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	records, err := c.listRecords(ctx, domainName(zone))
	if err != nil {
		return nil, err
	}

	result := make([]libdns.Record, 0, len(records))
	for _, r := range records {
		rec, err := fromAPI(r, zone)
		if err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	return result, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}

	var added []libdns.Record
	for _, rec := range recs {
		record, err := toAPI(rec)
		if err != nil {
			return added, err
		}
		created, err := c.addRecord(ctx, domainName(zone), record)
		if err != nil {
			return added, fmt.Errorf("yandex360: add %s record %q: %w", record.Type, record.Name, err)
		}
		// Fill in anything the API response may have omitted.
		if created.Type == "" {
			record.ID = created.ID
			created = record
		}
		addedRec, err := fromAPI(created, zone)
		if err != nil {
			return added, err
		}
		added = append(added, addedRec)
	}
	return added, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
// Empty type, TTL and value act as wildcards, as specified by libdns.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	domain := domainName(zone)

	existing, err := c.listRecords(ctx, domain)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	for _, r := range existing {
		rec, err := fromAPI(r, zone)
		if err != nil {
			continue // unparseable records can't match anything
		}
		if !matchesAny(rec.RR(), recs, zone) {
			continue
		}
		if err := c.deleteRecord(ctx, domain, r.ID); err != nil {
			return deleted, fmt.Errorf("yandex360: delete %s record %q: %w", r.Type, r.Name, err)
		}
		deleted = append(deleted, rec)
	}
	return deleted, nil
}

func matchesAny(have libdns.RR, recs []libdns.Record, zone string) bool {
	for _, rec := range recs {
		want := rec.RR()
		if relativeName(want.Name, zone) != have.Name {
			continue
		}
		if want.Type != "" && !strings.EqualFold(want.Type, have.Type) {
			continue
		}
		if want.TTL != 0 && want.TTL != have.TTL {
			continue
		}
		if want.Data != "" && strings.TrimSuffix(want.Data, ".") != strings.TrimSuffix(have.Data, ".") {
			continue
		}
		return true
	}
	return false
}

// domainName converts a libdns zone ("example.com.") to a Yandex 360 domain ("example.com").
func domainName(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

// relativeName normalizes a record name, which may be relative or fully
// qualified, to the libdns relative form ("@" for the zone apex).
func relativeName(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	domain := domainName(zone)
	switch {
	case name == "" || name == "@" || strings.EqualFold(name, domain):
		return "@"
	case len(name) > len(domain) && strings.EqualFold(name[len(name)-len(domain)-1:], "."+domain):
		return name[:len(name)-len(domain)-1]
	}
	return name
}

func fromAPI(r apiRecord, zone string) (libdns.Record, error) {
	name := relativeName(r.Name, zone)
	ttl := time.Duration(r.TTL) * time.Second

	switch strings.ToUpper(r.Type) {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(r.Address)
		if err != nil {
			return nil, fmt.Errorf("yandex360: record %d: invalid address %q: %w", r.ID, r.Address, err)
		}
		return libdns.Address{Name: name, TTL: ttl, IP: ip, ProviderData: r.ID}, nil
	case "CNAME":
		return libdns.CNAME{Name: name, TTL: ttl, Target: r.Target, ProviderData: r.ID}, nil
	case "NS":
		return libdns.NS{Name: name, TTL: ttl, Target: r.Target, ProviderData: r.ID}, nil
	case "MX":
		return libdns.MX{Name: name, TTL: ttl, Preference: uint16(r.Preference), Target: r.Exchange, ProviderData: r.ID}, nil
	case "TXT":
		return libdns.TXT{Name: name, TTL: ttl, Text: r.Text, ProviderData: r.ID}, nil
	case "CAA":
		return libdns.CAA{Name: name, TTL: ttl, Flags: uint8(r.Flag), Tag: r.Tag, Value: r.Value, ProviderData: r.ID}, nil
	case "SRV":
		rec, err := libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: "SRV",
			Data: fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target),
		}.Parse()
		if err != nil {
			return nil, fmt.Errorf("yandex360: record %d: %w", r.ID, err)
		}
		srv := rec.(libdns.SRV)
		srv.ProviderData = r.ID
		return srv, nil
	}
	return libdns.RR{Name: name, TTL: ttl, Type: r.Type}, nil
}

func toAPI(rec libdns.Record) (apiRecord, error) {
	rr := rec.RR()
	parsed, err := rr.Parse()
	if err != nil {
		return apiRecord{}, fmt.Errorf("yandex360: %w", err)
	}

	ttl := rr.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	r := apiRecord{
		Name: rr.Name,
		TTL:  int64(ttl / time.Second),
		Type: strings.ToUpper(rr.Type),
	}
	if r.Name == "" {
		r.Name = "@"
	}

	switch v := parsed.(type) {
	case libdns.Address:
		r.Address = v.IP.String()
	case libdns.CNAME:
		r.Target = strings.TrimSuffix(v.Target, ".")
	case libdns.NS:
		r.Target = strings.TrimSuffix(v.Target, ".")
	case libdns.MX:
		r.Preference = int64(v.Preference)
		r.Exchange = strings.TrimSuffix(v.Target, ".")
	case libdns.TXT:
		r.Text = v.Text
	case libdns.CAA:
		r.Flag = int64(v.Flags)
		r.Tag = v.Tag
		r.Value = v.Value
	case libdns.SRV:
		r.Priority = int64(v.Priority)
		r.Weight = int64(v.Weight)
		r.Port = int64(v.Port)
		r.Target = strings.TrimSuffix(v.Target, ".")
	default:
		return apiRecord{}, fmt.Errorf("yandex360: unsupported record type %q", rr.Type)
	}
	return r, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
