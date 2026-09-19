package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
)

const (
	apiBaseURL = "https://api.cloudflareclient.com"
	apiVersion = "v0a2158"
	userAgent  = "okhttp/3.12.1"
	timeout    = 20 * time.Second
)

// apiSpec describes one registration API version. Cloudflare rotates these;
// newer clients use PATCH to enable WARP, older ones accept warp_enabled inline.
type apiSpec struct {
	name       string
	version    string
	devType    string
	locale     string
	warpInBody bool
	extraHdrs  map[string]string
}

// registerAPIs is the failover chain: try each version until one responds.
// v0a2158 is first because it is known to work from this codebase.
var registerAPIs = []apiSpec{
	{"warp", apiVersion, "linux", "en_US", true, nil},
	{"warp-ios", "v0i1909051800", "ios", "en_US", false, nil},
	{"warp4", "v0a737", "linux", "en_US", false, nil},
	{"warp-pc", "v0a4005", "PC", "en_US", false, map[string]string{"CF-Client-Version": "a-6.30-3596"}},
}

func tosDate() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
	}
}

// NewClientWithUTLS creates a client with uTLS fingerprint rotation (stdlib + uTLS fallback).
// Useful in regions with TLS fingerprint blocking.
func NewClientWithUTLS() *Client {
	tr := &http.Transport{
		DialTLSContext: dialUTLSWithFallback,
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout, Transport: tr},
	}
}

// dialUTLSWithFallback tries stdlib TLS first, then uTLS Chrome/Firefox fingerprints.
func dialUTLSWithFallback(ctx context.Context, network, addr string) (net.Conn, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	// Tier 1: stdlib TLS
	tcpConn, err := new(net.Dialer).DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err == nil {
		return tlsConn, nil
	}
	tcpConn.Close()

	// Tier 2: uTLS Chrome fingerprint
	specs := []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
	}
	for _, spec := range specs {
		tcpConn, err := new(net.Dialer).DialContext(ctx, network, addr)
		if err != nil {
			continue
		}
		uConn := utls.UClient(tcpConn, &utls.Config{
			ServerName: "api.cloudflareclient.com",
			NextProtos: []string{"h2", "http/1.1"},
		}, spec)
		if err := uConn.Handshake(); err == nil {
			return uConn, nil
		}
		tcpConn.Close()
	}

	return nil, fmt.Errorf("all TLS methods failed")
}

func GenerateKeyPair() (privateKey, publicKey string, err error) {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64

	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, &sk)

	privateKey = base64.StdEncoding.EncodeToString(sk[:])
	publicKey = base64.StdEncoding.EncodeToString(pk[:])
	return privateKey, publicKey, nil
}

// regBody is the wire-format registration payload shared across API versions.
type regBody struct {
	Key         string `json:"key"`
	InstallID   string `json:"install_id"`
	FCMToken    string `json:"fcm_token"`
	Referer     string `json:"referer"`
	Type        string `json:"type,omitempty"`
	Model       string `json:"model,omitempty"`
	Name        string `json:"name,omitempty"`
	Tos         string `json:"tos,omitempty"`
	Locale      string `json:"locale,omitempty"`
	WarpEnabled bool   `json:"warp_enabled,omitempty"`
	License     string `json:"license,omitempty"`
}

// Register registers a new WARP account, trying the API failover chain.
// WARP is enabled via PATCH (the modern flow), and a license upgrades the
// account to WARP+ via PATCH /reg/{id}/account.
func (c *Client) Register(req *RegisterRequest) (*RegisterResponse, error) {
	var errs []string
	for _, spec := range registerAPIs {
		resp, err := c.registerSpec(spec, req)
		if err == nil {
			return resp, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", spec.version, err))
	}
	return nil, fmt.Errorf("all registration APIs failed: %s", strings.Join(errs, "; "))
}

func (c *Client) registerSpec(spec apiSpec, req *RegisterRequest) (*RegisterResponse, error) {
	tos := req.Tos
	if tos == "" {
		tos = tosDate()
	}
	body := regBody{
		Key:         req.Key,
		InstallID:   req.InstallID,
		FCMToken:    req.FCMToken,
		Referer:     req.Referer,
		Type:        spec.devType,
		Model:       req.Model,
		Name:        req.Name,
		Tos:         tos,
		Locale:      spec.locale,
		WarpEnabled: req.WarpEnabled,
		License:     req.License,
	}
	if !spec.warpInBody {
		body.WarpEnabled = false
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", apiBaseURL+"/"+spec.version+"/reg", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", userAgent)
	for k, v := range spec.extraHdrs {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result RegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w, body: %s", err, string(respBody))
	}

	// Modern flow: WARP is enabled by a follow-up PATCH.
	if !spec.warpInBody {
		if err := c.patchSpec(spec, result.ID, result.Token, `{"warp_enabled":true}`, ""); err != nil {
			return nil, fmt.Errorf("enable warp: %w", err)
		}
	}

	// WARP+ activation via account endpoint (works across API versions).
	if req.License != "" && result.ID != "" && result.Token != "" {
		if err := c.patchSpec(spec, result.ID, result.Token, "", req.License); err != nil {
			return nil, fmt.Errorf("apply WARP+ license: %w", err)
		}
	}

	return &result, nil
}

// patchSpec issues a PATCH against /reg/{id} (body) or /reg/{id}/account (license).
func (c *Client) patchSpec(spec apiSpec, id, token, body, license string) error {
	path := "/" + spec.version + "/reg/" + id
	if license != "" {
		path += "/account"
		body = fmt.Sprintf(`{"license":%q}`, license)
	}
	req, err := http.NewRequest("PATCH", apiBaseURL+path, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("create patch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("patch request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("patch error (status %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// KeepAlive re-enables WARP on the account, trying the API failover chain.
func (c *Client) KeepAlive(token, accountID string) error {
	var errs []string
	for _, spec := range registerAPIs {
		if err := c.patchSpec(spec, accountID, token, `{"warp_enabled":true}`, ""); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", spec.version, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("keepalive failed on all APIs: %s", strings.Join(errs, "; "))
}
