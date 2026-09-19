package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"warp-cli/config"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
)

const (
	verifyTopN        = 5
	verifyProbeTarget = "1.1.1.1"
	verifyPingCount   = 4
)

// isElevated reports whether the current process runs with administrator rights.
// TUN verification needs elevation (Wintun driver + route changes).
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// isTunnelActive reports whether a WARP tunnel (172.16.0.x) is already up.
// Verification cannot run while another tunnel owns that address space.
func isTunnelActive() bool {
	out, err := exec.Command("cmd", "/c", "netsh interface ip show addresses").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "172.16.0.")
}

// verifyEndpoints spins up a short-lived real tunnel to each candidate endpoint
// and pings the probe target through it. Endpoints whose tunnel dies right after
// the handshake (torn down by DPI) are flagged Torn, and every verified endpoint
// gets RTT/loss metrics. Results are re-ranked by endpointScore so a fast-but-torn
// endpoint never beats a stable one. The original slice is modified in place.
func verifyEndpoints(results []ScanResult, profile *config.Profile) []ScanResult {
	if profile == nil || profile.PrivateKey == "" || profile.PublicKey == "" {
		return results
	}
	if len(results) == 0 {
		return results
	}
	if !isElevated() {
		fmt.Println("  Phase 3: skipping TUN verification (run as Administrator to enable)")
		return results
	}
	if isTunnelActive() {
		fmt.Println("  Phase 3: skipping — a tunnel is already active (run 'awarp down' first)")
		return results
	}

	topN := verifyTopN
	if topN > len(results) {
		topN = len(results)
	}
	fmt.Printf("  Phase 3: verifying top %d endpoints through a real tunnel...\n", topN)
	for i := 0; i < topN; i++ {
		r := &results[i]
		replies, avgRTT := probeTunnelReplies(*r, profile)
		if replies < 0 {
			fmt.Printf("    %s:%d — NOT VERIFIED (tunnel setup failed)\n", r.IP, r.Port)
			continue
		}
		r.Verified = true
		if avgRTT == 0 && replies > 0 {
			avgRTT = r.Latency
		}
		r.TunnelRTT = avgRTT
		r.TunnelLoss = 100 - replies*100/verifyPingCount
		switch {
		case replies == 0:
			r.Torn = true
			fmt.Printf("    %s:%d — TORN DOWN (0/%d)\n", r.IP, r.Port, verifyPingCount)
		case r.TunnelLoss >= 50:
			fmt.Printf("    %s:%d — weak (%d/%d, %s avg)\n", r.IP, r.Port, replies, verifyPingCount, avgRTT.Round(time.Millisecond))
		default:
			fmt.Printf("    %s:%d — OK (%d/%d, %s avg)\n", r.IP, r.Port, replies, verifyPingCount, avgRTT.Round(time.Millisecond))
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		return endpointScore(results[i]) < endpointScore(results[j])
	})
	return results
}

// endpointScore ranks endpoints by real tunnel quality first, ICMP latency second:
//
//	verified healthy  → tunnel RTT + 2 ms per % loss (stability matters)
//	not verified      → ICMP latency + 30 ms penalty (unverified endpoints only win
//	                     if no healthy verified endpoint exists at that cost)
//	torn              → huge score, always last
//
// A 46 ms endpoint that dies after the handshake can never beat a stable 53 ms one.
func endpointScore(r ScanResult) float64 {
	if r.Torn {
		return 1e6 + float64(r.Latency)
	}
	if r.Verified {
		s := float64(r.TunnelRTT) / float64(time.Millisecond)
		s += float64(r.TunnelLoss) * 2
		return s
	}
	return float64(r.Latency)/float64(time.Millisecond) + 30
}

// probeTunnelReplies brings up a real AWG tunnel to the given endpoint, pings the
// probe target through it and returns the number of replies plus the average RTT.
// Returns (-1, 0) when the tunnel could not be set up.
func probeTunnelReplies(ep ScanResult, profile *config.Profile) (int, time.Duration) {
	const intf = "warpvfy"

	tunDev, err := tun.CreateTUN(intf, 1280)
	if err != nil {
		return -1, 0
	}

	// Ensure the probe-target route is removed even on early returns.
	defer func() {
		cmdRun(fmt.Sprintf("route delete %s mask 255.255.255.255", verifyProbeTarget))
		tunDev.Close()
	}()

	logger := &device.Logger{
		Verbosef: func(string, ...interface{}) {},
		Errorf:   func(string, ...interface{}) {},
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	defer dev.Close()

	uapiCmd, srcIP, err := buildVerifyUAPI(profile, ep)
	if err != nil || srcIP == nil {
		return -1, 0
	}
	if err := dev.IpcSet(uapiCmd); err != nil {
		return -1, 0
	}
	if err := dev.Up(); err != nil {
		return -1, 0
	}

	// Assign the client IP on the TUN adapter so ping replies have a source.
	if nt, ok := tunDev.(*tun.NativeTun); ok {
		luid := winipcfg.LUID(nt.LUID())
		luid.SetIPAddressesForFamily(windows.AF_INET, []net.IPNet{{
			IP:   srcIP,
			Mask: net.CIDRMask(32, 32),
		}})
	}

	// Allow time for the WireGuard handshake, then route the probe target via TUN.
	time.Sleep(1500 * time.Millisecond)
	cmdRun(fmt.Sprintf("route add %s mask 255.255.255.255 %s", verifyProbeTarget, srcIP.String()))

	ping := exec.Command("cmd", "/c", fmt.Sprintf(
		"ping -4 -n %d -w 500 -S %s %s", verifyPingCount, srcIP.String(), verifyProbeTarget))
	out, err := ping.CombinedOutput()
	if err != nil {
		// ping returns nonzero when all packets are lost — that is our torn signal.
		if strings.Contains(string(out), "Cannot") || strings.Contains(string(out), "не удается") {
			return -1, 0
		}
	}
	replies, avgMs := parsePingStats(string(out))
	return replies, time.Duration(avgMs * float64(time.Millisecond))
}

// parsePingStats counts ICMP replies and returns the average RTT in milliseconds
// from "Reply from ... time=Xms" / "Ответ от ... время=Xмс" lines.
func parsePingStats(out string) (replies int, avgMs float64) {
	re := regexp.MustCompile(`time[=<](\d+(?:\.\d+)?)\s*(?:ms|мс)`)
	var sum float64
	var cnt int
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Reply from") && !strings.Contains(line, "Ответ от") {
			continue
		}
		replies++
		if m := re.FindStringSubmatch(line); len(m) == 2 {
			if v, err := strconv.ParseFloat(m[1], 64); err == nil && v > 0 {
				sum += v
				cnt++
			}
		}
	}
	if cnt > 0 {
		avgMs = sum / float64(cnt)
	}
	return replies, avgMs
}

// buildVerifyUAPI builds a UAPI config string for a probe tunnel to a single
// endpoint. Mirrors the real tunnel settings so the probe measures what a real
// connection will do: junk (I1-I5), timings and client-side traffic padding
// (content_padding_addition / random_trailers / disable_cookies) are kept.
// Only WARP-incompatible options are dropped: s1-s4 prefix padding and
// header_protection_key (they change the wire format, see config.WarpUnsafeAWG).
func buildVerifyUAPI(profile *config.Profile, ep ScanResult) (string, net.IP, error) {
	awg := profile.AWG
	awg.S1, awg.S2, awg.S3, awg.S4 = 0, 0, 0, 0
	awg.HeaderProtectionKey = ""

	privHex, err := b64Hex(profile.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("private key: %w", err)
	}
	pubHex, err := b64Hex(profile.PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("public key: %w", err)
	}

	var b strings.Builder
	b.WriteString("private_key=" + privHex + "\n")
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", awg.Jc, awg.Jmin, awg.Jmax)
	fmt.Fprintf(&b, "s1=%d\ns2=%d\ns3=%d\ns4=%d\n", awg.S1, awg.S2, awg.S3, awg.S4)
	for _, h := range []struct{ name, val string }{
		{"h1", awg.H1}, {"h2", awg.H2}, {"h3", awg.H3}, {"h4", awg.H4},
	} {
		if h.val != "" && h.val != "0" {
			b.WriteString(h.name + "=" + h.val + "\n")
		}
	}
	for i, v := range []string{awg.I1, awg.I2, awg.I3, awg.I4, awg.I5} {
		if v != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, v)
		}
	}
	for _, t := range []struct{ name, val string }{
		{"rekey_after_time", awg.RekeyAfterTime},
		{"rekey_timeout", awg.RekeyTimeout},
		{"reject_after_time", awg.RejectAfterTime},
		{"keepalive_timeout", awg.KeepaliveTimeout},
		{"max_handshake_attempts", awg.MaxHandshakeAttempts},
	} {
		if t.val != "" {
			b.WriteString(t.name + "=" + t.val + "\n")
		}
	}
	if v := awg.ContentPaddingAddition; v != "" {
		b.WriteString("content_padding_addition=" + v + "\n")
	}
	if awg.RandomTrailers {
		b.WriteString("random_trailers=true\n")
	}
	if awg.DisableCookies {
		b.WriteString("disable_cookies=true\n")
	}
	pka := awg.PersistentKeepalive
	if pka == "" {
		pka = "25"
	}
	fmt.Fprintf(&b, "replace_peers=true\npublic_key=%s\nendpoint=%s:%d\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=%s\n",
		pubHex, ep.IP, ep.Port, pka)

	srcIP := clientIPv4(profile)
	if srcIP == nil {
		return "", nil, fmt.Errorf("no IPv4 client address in profile")
	}
	return b.String(), srcIP, nil
}

// clientIPv4 returns the /32 IPv4 client address from the profile (e.g. 172.16.0.2).
func clientIPv4(profile *config.Profile) net.IP {
	addr := profile.Address
	if idx := strings.Index(addr, "/"); idx != -1 {
		addr = addr[:idx]
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	return ip.To4()
}

// b64Hex decodes a base64 key and returns its hex representation for UAPI.
func b64Hex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// cmdRun executes a command line via cmd /c without caring about its result.
func cmdRun(line string) {
	exec.Command("cmd", "/c", line).Run()
}