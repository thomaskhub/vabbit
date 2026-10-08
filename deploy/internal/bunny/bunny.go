// Package bunny is a small client for the parts of the bunny.net API that
// EdgeGuard needs: storage zones and edge scripts.
package bunny

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultBaseURL = "https://api.bunny.net"

// ErrNotFound is returned when a lookup by name finds nothing.
var ErrNotFound = errors.New("not found")

type Client struct {
	base string
	key  string
	http *http.Client
}

// New returns a client. base must be https, except loopback addresses (tests).
func New(base, apiKey string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid Bunny API URL %q", base)
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("Bunny API URL must use https")
		}
	}
	if apiKey == "" {
		return nil, errors.New("missing Bunny API key")
	}
	return &Client{
		base: u.Scheme + "://" + u.Host,
		key:  apiKey,
		http: &http.Client{
			Timeout: 60 * time.Second,
			// The API key travels in a header; never let a redirect carry it elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// APIError is a non-2xx answer from the Bunny API.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("bunny API: %s (HTTP %d)", e.Message, e.Status)
	}
	return fmt.Sprintf("bunny API: HTTP %d", e.Status)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("AccessKey", c.key)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct{ Message string }
		_ = json.Unmarshal(data, &e)
		if res.StatusCode == http.StatusUnauthorized && e.Message == "" {
			e.Message = "API key rejected"
		}
		return &APIError{Status: res.StatusCode, Message: e.Message}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("bunny API: bad response for %s %s: %w", method, path, err)
		}
	}
	return nil
}

// ---- storage zones

type StorageZone struct {
	ID                 int64    `json:"Id"`
	Name               string   `json:"Name"`
	Password           string   `json:"Password"`
	Region             string   `json:"Region"`
	ReplicationRegions []string `json:"ReplicationRegions"`
	StorageHostname    string   `json:"StorageHostname"`
	PullZones          []struct {
		ID   int64  `json:"Id"`
		Name string `json:"Name"`
	} `json:"PullZones"`
	Deleted bool `json:"Deleted"`
}

func (c *Client) FindStorageZone(ctx context.Context, name string) (StorageZone, error) {
	var zones []StorageZone
	if err := c.do(ctx, "GET", "/storagezone?search="+url.QueryEscape(name), nil, &zones); err != nil {
		return StorageZone{}, err
	}
	for _, z := range zones {
		if z.Name == name && !z.Deleted {
			return z, nil
		}
	}
	return StorageZone{}, ErrNotFound
}

func (c *Client) CreateStorageZone(ctx context.Context, name, region string, replication []string) (StorageZone, error) {
	in := map[string]any{"Name": name, "Region": region}
	if len(replication) > 0 {
		in["ReplicationRegions"] = replication
	}
	var z StorageZone
	return z, c.do(ctx, "POST", "/storagezone", in, &z)
}

func (c *Client) DeleteStorageZone(ctx context.Context, id int64) error {
	return c.do(ctx, "DELETE", fmt.Sprintf("/storagezone/%d", id), nil, nil)
}

// ---- edge scripts

// ScriptTypeStandalone is a script served on its own pull zone hostname
// (the API calls it "CDN").
const ScriptTypeStandalone = 1

type Variable struct {
	ID           int64  `json:"Id"`
	Name         string `json:"Name"`
	Required     bool   `json:"Required"`
	DefaultValue string `json:"DefaultValue"`
}

type Script struct {
	ID              int64      `json:"Id"`
	Name            string     `json:"Name"`
	ScriptType      int        `json:"ScriptType"`
	Variables       []Variable `json:"EdgeScriptVariables"`
	Deleted         bool       `json:"Deleted"`
	DefaultHostname string     `json:"DefaultHostname"`
	SystemHostname  string     `json:"SystemHostname"`
	LinkedPullZones []struct {
		ID              int64  `json:"Id"`
		PullZoneName    string `json:"PullZoneName"`
		DefaultHostname string `json:"DefaultHostname"`
	} `json:"LinkedPullZones"`
}

// Hostname is where the script is served.
func (s Script) Hostname() string {
	for _, p := range s.LinkedPullZones {
		if p.DefaultHostname != "" {
			return p.DefaultHostname
		}
	}
	if s.DefaultHostname != "" {
		return s.DefaultHostname
	}
	return s.SystemHostname
}

func (s Script) Variable(name string) (Variable, bool) {
	for _, v := range s.Variables {
		if v.Name == name {
			return v, true
		}
	}
	return Variable{}, false
}

type scriptPage struct {
	Items        []Script `json:"Items"`
	HasMoreItems bool     `json:"HasMoreItems"`
}

func (c *Client) FindScript(ctx context.Context, name string) (Script, error) {
	for page := 1; page <= 100; page++ {
		var p scriptPage
		q := fmt.Sprintf("/compute/script?search=%s&includeLinkedPullzones=true&page=%d", url.QueryEscape(name), page)
		if err := c.do(ctx, "GET", q, nil, &p); err != nil {
			return Script{}, err
		}
		for _, s := range p.Items {
			if s.Name == name && !s.Deleted {
				return s, nil
			}
		}
		if !p.HasMoreItems {
			break
		}
	}
	return Script{}, ErrNotFound
}

func (c *Client) GetScript(ctx context.Context, id int64) (Script, error) {
	var s Script
	return s, c.do(ctx, "GET", fmt.Sprintf("/compute/script/%d", id), nil, &s)
}

// CreateScript creates a standalone script with its own linked pull zone,
// which gives it a public *.b-cdn.net hostname.
func (c *Client) CreateScript(ctx context.Context, name, code string) (Script, error) {
	in := map[string]any{
		"Name":                 name,
		"Code":                 code,
		"ScriptType":           ScriptTypeStandalone,
		"CreateLinkedPullZone": true,
		"LinkedPullZoneName":   name,
	}
	var s Script
	return s, c.do(ctx, "POST", "/compute/script", in, &s)
}

func (c *Client) DeleteScript(ctx context.Context, id int64) error {
	return c.do(ctx, "DELETE", fmt.Sprintf("/compute/script/%d?deleteLinkedPullZones=true", id), nil, nil)
}

type release struct {
	Code string `json:"Code"`
}

// ActiveCode returns the code of the live release ("" if none).
func (c *Client) ActiveCode(ctx context.Context, id int64) (string, error) {
	var r release
	err := c.do(ctx, "GET", fmt.Sprintf("/compute/script/%d/releases/active", id), nil, &r)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return "", nil
	}
	return r.Code, err
}

func (c *Client) SetCode(ctx context.Context, id int64, code string) error {
	return c.do(ctx, "POST", fmt.Sprintf("/compute/script/%d/code", id), map[string]any{"Code": code}, nil)
}

func (c *Client) UpsertVariable(ctx context.Context, id int64, name, value string) error {
	in := map[string]any{"Name": name, "Required": true, "DefaultValue": value}
	return c.do(ctx, "PUT", fmt.Sprintf("/compute/script/%d/variables", id), in, nil)
}

// SecretNames lists the names (never the values) of a script's secrets.
func (c *Client) SecretNames(ctx context.Context, id int64) (map[string]bool, error) {
	var out struct {
		Secrets []struct{ Name string } `json:"Secrets"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/compute/script/%d/secrets", id), nil, &out); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, s := range out.Secrets {
		names[s.Name] = true
	}
	return names, nil
}

func (c *Client) UpsertSecret(ctx context.Context, id int64, name, value string) error {
	in := map[string]any{"Name": name, "Secret": value}
	return c.do(ctx, "PUT", fmt.Sprintf("/compute/script/%d/secrets", id), in, nil)
}

func (c *Client) Publish(ctx context.Context, id int64, note string) error {
	return c.do(ctx, "POST", fmt.Sprintf("/compute/script/%d/publish", id), map[string]any{"Note": note}, nil)
}
