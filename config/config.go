package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type AWGConfig struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	S3   int    `json:"s3"`
	S4   int    `json:"s4"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
	I1   string `json:"i1"`
	I2   string `json:"i2"`
	I3   string `json:"i3"`
	I4   string `json:"i4"`
	I5   string `json:"i5"`

	// AWG 3+ features
	HeaderProtectionKey  string `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
	RekeyAfterTime       string `json:"rekey_after_time,omitempty"`
	RekeyTimeout         string `json:"rekey_timeout,omitempty"`
	RejectAfterTime      string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout     string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts string `json:"max_handshake_attempts,omitempty"`
	RandomTrailers       bool   `json:"random_trailers,omitempty"`
	DisableCookies       bool   `json:"disable_cookies,omitempty"`
	PersistentKeepalive  string `json:"persistent_keepalive,omitempty"`
}

type Profile struct {
	Name       string    `json:"name"`
	PrivateKey string    `json:"private_key"`
	Address    string    `json:"address"`
	Address6   string    `json:"address6"`
	DNS        string    `json:"dns"`
	PublicKey  string    `json:"public_key"`
	Endpoint   string    `json:"endpoint"`
	AccountID  string    `json:"account_id"`
	ClientID   string    `json:"client_id"`
	Token      string    `json:"token"`
	License    string    `json:"license,omitempty"`
	AWG        AWGConfig `json:"awg"`
}

var DefaultAWG = AWGConfig{
	Jc:   4,
	Jmin: 40,
	Jmax: 70,
	S1:   0,
	S2:   0,
	S3:   0,
	S4:   0,
	H1:   "1",
	H2:   "2",
	H3:   "3",
	H4:   "4",
	I1:   "<b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>",
	I2:   "<b 0xc3e997d813c83bd4fabb64c3bb55f2c79dbf2029f3644c712bb98c43b2a567c2e29e619f9af29c94c446366677b71e8d6242aa4f><b 0xc78d9335a3e916a97983ed43e5b5840104f235bf319d97695800a7ea5be0a24210425687d1>",
	I3:   "<b 0x0f105d889d45da204530d94fee024c8f8233ad4eb035c29012><b 0xf330b70583658f244d7c4827c8d0605eadde54841777e4395d92958096d3f7ff49809e2908a239746e1f9b5d7658><b 0xd06acdeb21134bbbbc849e57f30977251b279a>",
	I4:   "<b 0x145139934a01e8becbba168f3333b296c8454e796f78445c53802141c6dd761c6de9ee9a8baebb161d83ae62>",
	I5:   "<b 0x0199964affcf77d881ff8467f6b77adde4040d3a0f389506cce7656738f732211d1b62b5ce04>",

	// AWG 3.x WARP-safe defaults — client-side only (Cloudflare WARP = stock WireGuard).
	// Randomised timing windows mask the regular WireGuard rekey pattern for DPI.
	RekeyAfterTime:       "100-120",
	RekeyTimeout:         "3-7",
	RejectAfterTime:      "150-180",
	KeepaliveTimeout:     "5-15",
	MaxHandshakeAttempts: "15-20",
	PersistentKeepalive:  "25-35",

	// Client-side traffic padding (per amneziawg-go v3.1 send.go): pads the INNER
	// packet with trailing zeroes before AEAD seal, capped by the observed UDP
	// window. A stock WireGuard receiver (WARP) tolerates the trailing bytes,
	// and DPI can no longer fingerprint the tunnel by the classic WG packet-size
	// signature (multiples of 16 + 16-byte auth tag). Local DPI often throttles
	// or resets long-lived WG flows detected by size — randomising sizes stabilises.
	ContentPaddingAddition: "10-100",
	RandomTrailers:         true,
	DisableCookies:         true,
}

var DefaultEndpoint = "engage.cloudflareclient.com:2408"
var DefaultPublicKey = "bmeXGQk63OMlpJOfmO2B+LHBWNt4VSMHi1kU5Kj7wRc="
var DefaultDNS = "1.1.1.1"

// warpIPRanges are the Cloudflare WARP server front ranges. WARP peers are stock
// WireGuard servers, so only client-side AmneziaWG obfuscation works against them.
var warpIPRanges = []string{
	"162.159.192.0/21",
	"188.114.96.0/20",
	"141.101.112.0/20",
	"8.6.112.0/24",
	"8.34.70.0/24",
	"8.34.146.0/24",
	"8.35.211.0/24",
	"8.39.125.0/24",
	"8.39.204.0/24",
	"8.39.214.0/24",
	"8.47.69.0/24",
	"162.159.204.0/24",
	"104.16.60.8/32",
	"104.16.61.8/32",
	"104.18.20.250/32",
	"104.18.21.250/32",
	"172.67.135.50/32",
	"172.67.136.50/32",
	"172.67.170.10/32",
	"172.67.171.10/32",
}

// IsWarpEndpoint reports whether the endpoint host belongs to the Cloudflare WARP
// front (by hostname or known WARP IP range).
func IsWarpEndpoint(endpoint string) bool {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "engage.cloudflareclient.com" || strings.HasSuffix(host, ".cloudflareclient.com") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return false
	}
	for _, r := range warpIPRanges {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// WarpUnsafeAWG returns a list of AWG settings that are known to be INCOMPATIBLE
// with Cloudflare WARP and may break the WireGuard handshake or tunnel.
//
// Cloudflare WARP = stock WireGuard server. Compatible client-side only:
// junk (jc/jmin/jmax), I1-I5 noise, timings, persistent_keepalive AND inner-packet
// trailing padding (content_padding_addition, random_trailers — pads INSIDE the
// AEAD payload, plain WG receiver ignores the trailing bytes) plus disable_cookies.
//
// BREAKS the wire format with a plain WG peer (must stay off for WARP):
// s1-s4 (prefix padding on handshake/transport messages) and
// header_protection_key (XORs header fields; only meaningful together with s-padding).
func WarpUnsafeAWG(awg AWGConfig) []string {
	var out []string
	for _, s := range []struct{ name string; val int }{
		{"s1", awg.S1}, {"s2", awg.S2}, {"s3", awg.S3}, {"s4", awg.S4},
	} {
		if s.val > 0 {
			out = append(out, fmt.Sprintf("%s=%d (WARP = stock WireGuard, prefix padding changes the wire format and breaks the handshake)", s.name, s.val))
		}
	}
	if awg.HeaderProtectionKey != "" {
		out = append(out, "header_protection_key (header XOR requires the AWG server to strip it; with a plain WARP peer it corrupts message headers)")
	}
	return out
}

func ProfilesDir() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "profiles")
}

func ProfilePath(name string) string {
	return filepath.Join(ProfilesDir(), name+".json")
}

func (p *Profile) Save() error {
	dir := ProfilesDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create profiles dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	if err := os.WriteFile(ProfilePath(p.Name), data, 0600); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}
	return nil
}

func LoadProfile(name string) (*Profile, error) {
	data, err := os.ReadFile(ProfilePath(name))
	if err != nil {
		return nil, fmt.Errorf("read profile %q: %w", name, err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal profile %q: %w", name, err)
	}
	if p.Endpoint == "" {
		p.Endpoint = DefaultEndpoint
	}
	if p.PublicKey == "" {
		p.PublicKey = DefaultPublicKey
	}
	if p.DNS == "" {
		p.DNS = DefaultDNS
	}
	return &p, nil
}

func ListProfiles() ([]string, error) {
	dir := ProfilesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name()[:len(e.Name())-5])
		}
	}
	return names, nil
}

func DeleteProfile(name string) error {
	return os.Remove(ProfilePath(name))
}
