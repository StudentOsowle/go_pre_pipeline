package waf

import (
	"log"
	"net"
	"net/http"
	"time"
)

type Verdict int

const (
	Allow Verdict = iota
	Block
	Flag
)

type Inspector struct {
	Blocklist *Blocklist
	Beacon    *BeaconDetector
	Logger    *log.Logger

	AutoBlockOnBeacon bool
}

func (in *Inspector) Inspect(r *http.Request) (Verdict, string) {
	ip := clientIP(r)

	if ip != nil && in.Blocklist.Contains(ip) {
		return Block, "source IP on blocklist (known-bad infrastructure)"
	}

	ua := r.UserAgent()
	if IsSuspiciousUserAgent(ua) && !IsGitClient(ua) {
		return Block, "suspicious User-Agent signature: " + safeUA(ua)
	}

	if ip != nil {
		if in.Beacon.Observe(ip.String(), time.Now()) {
			if in.AutoBlockOnBeacon {
				in.Blocklist.Add(ip)
				return Block, "regular check-in interval detected (beaconing) — auto-blocked"
			}
			return Flag, "regular check-in interval detected (beaconing)"
		}
	}

	return Allow, ""
}

func (in *Inspector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verdict, reason := in.Inspect(r)

		switch verdict {
		case Block:
			in.Logger.Printf("BLOCKED ip=%s path=%s ua=%q reason=%s",
				clientIPString(r), r.URL.Path, r.UserAgent(), reason)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		case Flag:
			in.Logger.Printf("FLAGGED ip=%s path=%s ua=%q reason=%s",
				clientIPString(r), r.URL.Path, r.UserAgent(), reason)
		}

		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func clientIPString(r *http.Request) string {
	if ip := clientIP(r); ip != nil {
		return ip.String()
	}
	return r.RemoteAddr
}

func safeUA(ua string) string {
	if len(ua) > 200 {
		return ua[:200] + "...(truncated)"
	}
	return ua
}
