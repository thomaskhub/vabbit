// Package api is a minimal client for the EdgeGuard control plane.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
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

const maxResponse = 1 << 20

// ErrUnauthorized means the server rejected the credential (e.g. device removed).
var ErrUnauthorized = errors.New("unauthorized")

type Client struct {
	base  string
	token string
	http  *http.Client
}

// ValidateServer checks a control plane URL. Plain http is only allowed for
// loopback addresses so tokens never cross a network unencrypted.
func ValidateServer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("server URL must be just scheme://host[:port]")
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("refusing plain http to %s; use https", host)
		}
	default:
		return "", fmt.Errorf("server URL must use https")
	}
	return u.Scheme + "://" + u.Host, nil
}

func New(server, token string) (*Client, error) {
	base, err := ValidateServer(server)
	if err != nil {
		return nil, err
	}
	return &Client{
		base:  base,
		token: token,
		http: &http.Client{
			Timeout:   20 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment},
			// Never follow redirects: a redirect could leak the bearer token.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
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
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusUnauthorized {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error != "" && e.Error != "unauthorized" {
			return fmt.Errorf("%w: %s", ErrUnauthorized, e.Error)
		}
		return ErrUnauthorized
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct{ Error string }
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("server: %s (HTTP %d)", e.Error, res.StatusCode)
		}
		return fmt.Errorf("server returned HTTP %d", res.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("bad response from server: %w", err)
		}
	}
	return nil
}

type Network struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

type Device struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	PublicKey string  `json:"publicKey"`
	IP        string  `json:"ip"`
	Endpoint  *string `json:"endpoint"`
	Hub       bool    `json:"hub"`
	CreatedAt string  `json:"createdAt"`
	LastSeen  string  `json:"lastSeen"`
}

type SetupKey struct {
	Key       string `json:"key,omitempty"`
	ID        string `json:"id"`
	Reusable  bool   `json:"reusable"`
	MaxUses   int    `json:"maxUses"`
	Uses      int    `json:"uses"`
	ExpiresAt string `json:"expiresAt"`
}

type Peer struct {
	Name      string   `json:"name"`
	PublicKey string   `json:"publicKey"`
	IP        string   `json:"ip"`
	Hub       bool     `json:"hub"`
	Endpoints []string `json:"endpoints"`
}

type SyncResponse struct {
	Self    Device  `json:"self"`
	Network Network `json:"network"`
	Address string  `json:"address"`
	Peers   []Peer  `json:"peers"`
}

type EnrollRequest struct {
	SetupKey  string `json:"setupKey"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
	Endpoint  string `json:"endpoint,omitempty"`
}

type EnrollResponse struct {
	Device      Device  `json:"device"`
	DeviceToken string  `json:"deviceToken"`
	Network     Network `json:"network"`
}

func (c *Client) Network(ctx context.Context) (Network, error) {
	var n Network
	return n, c.do(ctx, "GET", "/api/v1/network", nil, &n)
}

func (c *Client) CreateSetupKey(ctx context.Context, reusable bool, maxUses int, ttl time.Duration) (SetupKey, error) {
	in := map[string]any{"reusable": reusable, "ttlSeconds": int(ttl.Seconds())}
	if maxUses > 0 {
		in["maxUses"] = maxUses
	}
	var k SetupKey
	return k, c.do(ctx, "POST", "/api/v1/setup-keys", in, &k)
}

func (c *Client) ListSetupKeys(ctx context.Context) ([]SetupKey, error) {
	var out struct{ SetupKeys []SetupKey }
	return out.SetupKeys, c.do(ctx, "GET", "/api/v1/setup-keys", nil, &out)
}

func (c *Client) DeleteSetupKey(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/api/v1/setup-keys/"+url.PathEscape(id), nil, nil)
}

func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	var out struct{ Devices []Device }
	return out.Devices, c.do(ctx, "GET", "/api/v1/devices", nil, &out)
}

func (c *Client) DeleteDevice(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/api/v1/devices/"+url.PathEscape(id), nil, nil)
}

func (c *Client) UpdateDevice(ctx context.Context, id string, patch map[string]any) (Device, error) {
	var out struct{ Device Device }
	return out.Device, c.do(ctx, "PATCH", "/api/v1/devices/"+url.PathEscape(id), patch, &out)
}

func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	var out EnrollResponse
	return out, c.do(ctx, "POST", "/api/v1/enroll", req, &out)
}

// Sync reports this device's static endpoint and NAT traversal candidates and
// returns the current peer list. nil candidates leaves the stored ones alone
// (used by status and other one-off calls); an empty slice clears them.
func (c *Client) Sync(ctx context.Context, endpoint string, candidates []string) (SyncResponse, error) {
	in := map[string]any{}
	if candidates != nil {
		in["candidates"] = candidates
	}
	if endpoint != "" {
		in["endpoint"] = endpoint
	}
	var out SyncResponse
	return out, c.do(ctx, "POST", "/api/v1/sync", in, &out)
}

// Leave removes the calling device from the network.
func (c *Client) Leave(ctx context.Context) error {
	return c.do(ctx, "DELETE", "/api/v1/device", nil, nil)
}
