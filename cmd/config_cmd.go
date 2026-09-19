package cmd

import (
	"fmt"
	"strings"

	"warp-cli/config"
	"warp-cli/tunnel"
)

func ConfigSet(profileName string, awgArgs []string, endpoint string) error {
	profile, err := config.LoadProfile(profileName)
	if err != nil {
		return fmt.Errorf("load profile %q: %w", profileName, err)
	}

	changed := false

	if endpoint != "" {
		if !strings.Contains(endpoint, ":") {
			return fmt.Errorf("invalid endpoint format %q: expected host:port (e.g. 162.159.193.1:2408)", endpoint)
		}
		host, port, _ := strings.Cut(endpoint, ":")
		if host == "" || port == "" {
			return fmt.Errorf("invalid endpoint format %q: expected host:port", endpoint)
		}
		profile.Endpoint = endpoint
		changed = true
		fmt.Printf("Endpoint: %s\n", endpoint)
	}

	if len(awgArgs) > 0 {
		awg, err := ParseAWGArgs(awgArgs)
		if err != nil {
			return err
		}
		profile.AWG = awg
		changed = true
	}

	// Warn if the profile now targets Cloudflare WARP with AWG options it cannot use.
	warpTarget := config.IsWarpEndpoint(profile.Endpoint)
	if changed && warpTarget {
		for _, w := range config.WarpUnsafeAWG(profile.AWG) {
			fmt.Printf("WARNING: %s — incompatible with Cloudflare WARP\n", w)
		}
	}

	if !changed {
		fmt.Println("Nothing to change. Use --endpoint or --set-awg.")
		return nil
	}

	if err := profile.Save(); err != nil {
		return fmt.Errorf("save profile: %w", err)
	}

	fmt.Printf("Profile %q updated.\n", profileName)
	if len(awgArgs) > 0 {
		printAWGConfig(profile.AWG)
	}
	return nil
}

func ConfigShow(profileName string) error {
	profile, err := config.LoadProfile(profileName)
	if err != nil {
		return fmt.Errorf("load profile %q: %w", profileName, err)
	}

	fmt.Printf("Profile:  %s\n", profile.Name)
	fmt.Printf("Address:  %s\n", profile.Address)
	if profile.Address6 != "" {
		fmt.Printf("Address6: %s\n", profile.Address6)
	}
	fmt.Printf("DNS:      %s\n", profile.DNS)
	fmt.Printf("Endpoint: %s\n", profile.Endpoint)
	fmt.Printf("Public:   %s\n", profile.PublicKey)
	fmt.Printf("ClientID: %s\n", profile.ClientID)
	if profile.License != "" {
		fmt.Printf("License:  %s\n", profile.License)
	}
	fmt.Println()

	printAWGConfig(profile.AWG)
	return nil
}

func ConfigProfiles() error {
	names, err := config.ListProfiles()
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}
	if len(names) == 0 {
		fmt.Println("No profiles found.")
		fmt.Println("Use: warp-cli register --profile <name>")
		return nil
	}
	fmt.Println("Profiles:")
	for _, name := range names {
		p, err := config.LoadProfile(name)
		if err != nil {
			fmt.Printf("  %s (error: %v)\n", name, err)
			continue
		}
		fmt.Printf("  %-15s %s\n", name, p.Address)
	}
	return nil
}

func ConfigDelete(profileName string) error {
	if err := config.DeleteProfile(profileName); err != nil {
		return fmt.Errorf("delete profile %q: %w", profileName, err)
	}
	fmt.Printf("Profile %q deleted.\n", profileName)
	return nil
}

func printAWGConfig(awg config.AWGConfig) {
	fmt.Println("AmneziaWG parameters:")
	fmt.Printf("  jc=%d  jmin=%d  jmax=%d\n", awg.Jc, awg.Jmin, awg.Jmax)
	fmt.Printf("  s1=%d  s2=%d  s3=%d  s4=%d\n", awg.S1, awg.S2, awg.S3, awg.S4)
	fmt.Printf("  h1=%s  h2=%s\n", awg.H1, awg.H2)
	fmt.Printf("  h3=%s  h4=%s\n", awg.H3, awg.H4)

	hasI := false
	for i, v := range []string{awg.I1, awg.I2, awg.I3, awg.I4, awg.I5} {
		if v != "" {
			if !hasI {
				fmt.Print("  custom: ")
				hasI = true
			}
			fmt.Printf("i%d=%s ", i+1, v)
		}
	}
	if hasI {
		fmt.Println()
	}

	printStr := func(name, v string) {
		if v != "" {
			fmt.Printf("  %s=%s\n", name, v)
		}
	}
	printStr("header_protection_key", awg.HeaderProtectionKey)
	printStr("content_padding_addition", awg.ContentPaddingAddition)
	printStr("rekey_after_time", awg.RekeyAfterTime)
	printStr("rekey_timeout", awg.RekeyTimeout)
	printStr("reject_after_time", awg.RejectAfterTime)
	printStr("keepalive_timeout", awg.KeepaliveTimeout)
	printStr("max_handshake_attempts", awg.MaxHandshakeAttempts)
	if awg.RandomTrailers {
		fmt.Println("  random_trailers=true")
	}
	if awg.DisableCookies {
		fmt.Println("  disable_cookies=true")
	}
	if awg.PersistentKeepalive != "" {
		fmt.Printf("  persistent_keepalive=%s\n", awg.PersistentKeepalive)
	}
}

func ParseAWGArgs(args []string) (config.AWGConfig, error) {
	return tunnel.ParseAWGArgs(args)
}

func Help() {
	const help = `awarp — WARP tunnel via AmneziaWG

USAGE:
  awarp register --profile <name> [--license KEY] [--set-awg KEY=VAL ...]
  awarp up --profile <name>
  awarp down --profile <name>
  awarp status --profile <name>
  awarp scan
  awarp config show --profile <name>
  awarp config set --profile <name> [--endpoint IP:PORT] [--set-awg KEY=VAL ...]
  awarp config profiles
  awarp config delete --profile <name>
  awarp conf [--profile <name>] [-o file.conf]   export AmneziaWG .conf
  awarp help

AWG PARAMETERS:
  jc, jmin, jmax   Junk packets
  s1-s4            Message paddings
  h1-h4            Message headers
  i1-i5            Custom signature packets
  header_protection_key   AWG 3+ header protection key (hex)
  content_padding_addition  AWG 3+ content padding range, e.g. 10-100
  rekey_after_time/    AWG 3+ custom timings (seconds range),
  rekey_timeout        e.g. 120-180
  reject_after_time
  keepalive_timeout    keepalive timeout range
  max_handshake_attempts  handshake retry range
  persistent_keepalive  keepalive interval or range, e.g. 25 or 25-35
  random_trailers       AWG 3.1: append random bytes to packets (true/false)
  disable_cookies       AWG 3.1: disable cookie replies (true/false)

WARP-SAFE:
  Cloudflare WARP peers are stock WireGuard servers. Client-side options
  work: jc/jmin/jmax, i1-i5, timings, persistent_keepalive and traffic
  padding (content_padding_addition, random_trailers, disable_cookies).
  s1-s4 and header_protection_key change the wire format and break the
  WARP handshake — a warning is shown when they are set on a WARP endpoint.

FLAGS:
  --community       Use community endpoint list (with scan)
  --fast            Scan only 8 common ports (faster)
  --full-as         Scan all Cloudflare AS prefixes (maximum coverage)
  --auto            Register + optimize endpoint in one command
  --i1-mode MODE    I1 generation: legacy, reorder, safe (default: safe)
  --sni DOMAIN      Generate I1 from SNI domain

ENDPOINTS:
  Default: engage.cloudflareclient.com:2408
  Direct IP: 162.159.193.1:2408
  Scan for fast endpoints: awarp scan
  Change endpoint: awarp config set --profile <name> --endpoint IP:PORT

NOTE:  'up' command requires Administrator privileges.
       Run the terminal as Administrator before using it.

EXAMPLES:
  awarp register --profile mywarp
  awarp register --profile mywarp --license XXXXXX
  awarp register --profile mywarp --auto           # register + scan best endpoint
  awarp up --profile mywarp
  awarp scan
  awarp scan --fast                                # scan only 8 common ports
  awarp scan --community                            # scan with community list
  awarp scan --full-as                              # scan all AS prefixes
  awarp config set --profile mywarp --endpoint 162.159.192.179:2408
  awarp config set --profile mywarp --set-awg jmin=100
  awarp conf --profile mywarp -o mywarp.conf   # export .conf (AmneziaWG)
`
	fmt.Print(help)
}


