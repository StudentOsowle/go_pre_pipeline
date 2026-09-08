package waf

import (
	"fmt"
	"net"
	"net/http"
)

// OutboundGuard wraps an http.RoundTripper and blocks any outgoing request
// whose destination host resolves to an IP on the outbound blocklist.
type OutboundGuard struct {
	Blocklist *Blocklist
	Transport http.RoundTripper
	Logger    interface{ Printf(string, ...any) }
}

func (g *OutboundGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()

	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if g.Blocklist.Contains(ip) {
				if g.Logger != nil {
					g.Logger.Printf("BLOCKED outbound destination host=%s ip=%s reason=destination on outbound blocklist", host, ip)
				}
				return nil, fmt.Errorf("blocked: outbound destination %s (%s) is on the blocklist", host, ip)
			}
		}
	}

	transport := g.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}

// AllowlistGuard wraps an http.RoundTripper and flags/blocks any outgoing
// request whose destination is NOT on the explicit allowlist. Used in the
// CI sandbox stage to catch "phone home" / unauthorized exfiltration
// attempts in freshly-built code, as opposed to OutboundGuard's blocklist
// approach used at runtime.
type AllowlistGuard struct {
	Allowlist  []string // exact hostnames permitted, e.g. "127.0.0.1:3000"
	Transport  http.RoundTripper
	Logger     interface{ Printf(string, ...any) }
	Violations *[]string // pointer so the caller can inspect what was blocked
}

func (g *AllowlistGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host

	allowed := false
	for _, a := range g.Allowlist {
		if host == a {
			allowed = true
			break
		}
	}

	if !allowed {
		msg := fmt.Sprintf("UNAUTHORIZED OUTBOUND ATTEMPT: %s", host)
		if g.Logger != nil {
			g.Logger.Printf(msg)
		}
		if g.Violations != nil {
			*g.Violations = append(*g.Violations, host)
		}
		return nil, fmt.Errorf("blocked: destination %s is not on the allowlist", host)
	}

	transport := g.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}
