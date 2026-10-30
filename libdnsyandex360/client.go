package libdnsyandex360

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const defaultBaseURL = "https://api360.yandex.net/"

// apiRecord is a DNS record as represented by the Yandex 360 API.
// https://yandex.ru/dev/api360/doc/ref/DomainDNSService/
type apiRecord struct {
	ID         int64  `json:"recordId,omitempty"`
	Address    string `json:"address,omitempty"`
	Exchange   string `json:"exchange,omitempty"`
	Flag       int64  `json:"flag,omitempty"`
	Name       string `json:"name,omitempty"`
	Port       int64  `json:"port,omitempty"`
	Preference int64  `json:"preference,omitempty"`
	Priority   int64  `json:"priority,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Target     string `json:"target,omitempty"`
	Text       string `json:"text,omitempty"`
	TTL        int64  `json:"ttl,omitempty"`
	Type       string `json:"type,omitempty"`
	Value      string `json:"value,omitempty"`
	Weight     int64  `json:"weight,omitempty"`
}

type listResponse struct {
	Records []apiRecord `json:"records"`
	Page    int         `json:"page"`
	Pages   int         `json:"pages"`
	PerPage int         `json:"perPage"`
	Total   int         `json:"total"`
}

// APIError is an error returned by the Yandex 360 API.
type APIError struct {
	StatusCode int      `json:"-"`
	Code       int32    `json:"code"`
	Message    string   `json:"message"`
	Details    []Detail `json:"details"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("yandex360: status %d: code %d: %s %v", e.StatusCode, e.Code, e.Message, e.Details)
}

// Detail is an additional error detail returned by the Yandex 360 API.
type Detail struct {
	Type string `json:"@type"`
}

func (d Detail) String() string { return d.Type }

type client struct {
	token      string
	orgID      int64
	baseURL    *url.URL
	httpClient *http.Client
}

func (c *client) dnsEndpoint(domain string, elem ...string) *url.URL {
	return c.baseURL.JoinPath(append([]string{"directory", "v1", "org", strconv.FormatInt(c.orgID, 10), "domains", domain, "dns"}, elem...)...)
}

// listRecords returns all DNS records of the domain.
// GET /directory/v1/org/{orgId}/domains/{domain}/dns
func (c *client) listRecords(ctx context.Context, domain string) ([]apiRecord, error) {
	var records []apiRecord
	for page := 1; ; page++ {
		endpoint := c.dnsEndpoint(domain)
		query := endpoint.Query()
		query.Set("page", strconv.Itoa(page))
		query.Set("perPage", "100")
		endpoint.RawQuery = query.Encode()

		var resp listResponse
		if err := c.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
			return nil, err
		}
		records = append(records, resp.Records...)

		if len(resp.Records) == 0 || page >= resp.Pages {
			return records, nil
		}
	}
}

// addRecord creates a DNS record.
// POST /directory/v1/org/{orgId}/domains/{domain}/dns
func (c *client) addRecord(ctx context.Context, domain string, record apiRecord) (apiRecord, error) {
	var created apiRecord
	err := c.do(ctx, http.MethodPost, c.dnsEndpoint(domain), record, &created)
	return created, err
}

// deleteRecord deletes a DNS record.
// DELETE /directory/v1/org/{orgId}/domains/{domain}/dns/{recordId}
func (c *client) deleteRecord(ctx context.Context, domain string, recordID int64) error {
	return c.do(ctx, http.MethodDelete, c.dnsEndpoint(domain, strconv.FormatInt(recordID, 10)), nil, nil)
}

func (c *client) do(ctx context.Context, method string, endpoint *url.URL, payload, result any) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("yandex360: encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("yandex360: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "OAuth "+c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("yandex360: %s %s: %w", method, endpoint.Path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("yandex360: read response: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		if json.Unmarshal(raw, apiErr) != nil || apiErr.Message == "" {
			apiErr.Message = strings.TrimSpace(string(raw))
		}
		return apiErr
	}

	if result == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("yandex360: decode response: %w", err)
	}
	return nil
}
