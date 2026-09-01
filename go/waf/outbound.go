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
					g.Logger.Printf("BLOCKED outbound desitnation host=%s ip=%s reason=destination on outbound blocklist", host, ip)
				}
				return nil, fmt.Errorf("blocked: outbound destinatioin %s (%s) is on the blocklist", host, ip)
			}
		}
	}

	transport := g.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}
