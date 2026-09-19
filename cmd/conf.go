package cmd

import (
	"fmt"
	"os"
	"strings"

	"warp-cli/config"
)

// ExportConf renders the profile as an AmneziaWG-compatible .conf file
// (the format used by AmneziaVPN/WireGuard clients, see issue #2) and writes
// it to output ("-" prints to stdout, default <profile>.conf).
func ExportConf(profileName, output string) error {
	profile, err := config.LoadProfile(profileName)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}

	if output == "" {
		output = profileName + ".conf"
	}

	var b strings.Builder

	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + profile.PrivateKey + "\n")

	addrs := profile.Address
	for _, a := range []string{profile.Address6} {
		if a != "" {
			addrs += ", " + a
		}
	}
	b.WriteString("Address = " + addrs + "\n")

	dns := profile.DNS
	if dns == "" {
		dns = config.DefaultDNS
	}
	for _, extra := range []string{"1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"} {
		if !containsHost(dns, extra) {
			if dns != "" {
				dns += ", "
			}
			dns += extra
		}
	}
	b.WriteString("DNS = " + dns + "\n")
	b.WriteString("MTU = 1280\n")

	awg := profile.AWG
	b.WriteString(fmt.Sprintf("Jc = %d\n", awg.Jc))
	b.WriteString(fmt.Sprintf("Jmin = %d\n", awg.Jmin))
	b.WriteString(fmt.Sprintf("Jmax = %d\n", awg.Jmax))
	b.WriteString(fmt.Sprintf("S1 = %d\n", awg.S1))
	b.WriteString(fmt.Sprintf("S2 = %d\n", awg.S2))
	b.WriteString(fmt.Sprintf("S3 = %d\n", awg.S3))
	b.WriteString(fmt.Sprintf("S4 = %d\n", awg.S4))
	for _, h := range []struct{ name, val string }{
		{"H1", awg.H1}, {"H2", awg.H2}, {"H3", awg.H3}, {"H4", awg.H4},
	} {
		if h.val != "" && h.val != "0" {
			b.WriteString(h.name + " = " + h.val + "\n")
		}
	}
	for i, v := range []string{awg.I1, awg.I2, awg.I3, awg.I4, awg.I5} {
		if v != "" {
			fmt.Fprintf(&b, "I%d = %s\n", i+1, v)
		}
	}
	if awg.HeaderProtectionKey != "" {
		b.WriteString("HeaderProtectionKey = " + awg.HeaderProtectionKey + "\n")
	}
	if awg.ContentPaddingAddition != "" {
		b.WriteString("ContentPaddingAddition = " + awg.ContentPaddingAddition + "\n")
	}
	for _, t := range []struct{ name, val string }{
		{"RekeyAfterTime", awg.RekeyAfterTime},
		{"RekeyTimeout", awg.RekeyTimeout},
		{"RejectAfterTime", awg.RejectAfterTime},
		{"KeepaliveTimeout", awg.KeepaliveTimeout},
		{"MaxHandshakeAttempts", awg.MaxHandshakeAttempts},
	} {
		if t.val != "" {
			b.WriteString(t.name + " = " + t.val + "\n")
		}
	}
	if awg.RandomTrailers {
		b.WriteString("RandomTrailers = on\n")
	}
	if awg.DisableCookies {
		b.WriteString("DisableCookies = on\n")
	}

	endpoint := profile.Endpoint
	if endpoint == "" {
		endpoint = config.DefaultEndpoint
	}
	pka := awg.PersistentKeepalive
	if pka == "" {
		pka = "25-35"
	}

	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + profile.PublicKey + "\n")
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	b.WriteString("Endpoint = " + endpoint + "\n")
	b.WriteString("PersistentKeepalive = " + pka + "\n")

	if output == "-" {
		fmt.Print(b.String())
		return nil
	}

	if err := os.WriteFile(output, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write conf: %w", err)
	}
	fmt.Printf("Configuration saved to: %s\n", output)
	return nil
}

// containsHost reports whether the CSV DNS list already contains s.
func containsHost(list, s string) bool {
	for _, part := range strings.Split(list, ",") {
		if strings.TrimSpace(part) == s {
			return true
		}
	}
	return false
}