package waf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Blocklist struct {
	mu      sync.RWMutex
	ips     map[string]struct{}
	cidrs   []*net.IPNet
	dynamic map[string]struct{} // IPs added at runtime via Add(), preserved across reloads
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		ips:     make(map[string]struct{}),
		dynamic: make(map[string]struct{}),
	}
}

// normalize converts IPv4-mapped IPv6 addresses (::ffff:127.0.0.1) to plain
// IPv4 form so they match blocklist entries written as "127.0.0.1".
func normalize(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func (b *Blocklist) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("opening blocklist %s: %w", path, err)
	}
	defer f.Close()

	ips := make(map[string]struct{})
	var cidrs []*net.IPNet

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "waf: skipping invalid CIDR entry %q: %v\n", line, err)
				continue
			}
			cidrs = append(cidrs, ipnet)
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "waf: skipping invalid IP entry %q\n", line)
			continue
		}
		ips[normalize(ip).String()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	// Merge in any runtime-added IPs so a file reload doesn't silently
	// un-block addresses that beacon/C2 detection added dynamically.
	for ip := range b.dynamic {
		ips[ip] = struct{}{}
	}
	b.ips = ips
	b.cidrs = cidrs
	b.mu.Unlock()
	return nil
}

func (b *Blocklist) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip = normalize(ip)

	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.ips[ip.String()]; ok {
		return true
	}
	for _, cidr := range b.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (b *Blocklist) Add(ip net.IP) {
	if ip == nil {
		return
	}
	ip = normalize(ip)

	b.mu.Lock()
	b.ips[ip.String()] = struct{}{}
	b.dynamic[ip.String()] = struct{}{}
	b.mu.Unlock()
}

// Remove clears an IP from both the active and dynamic sets. Useful for
// manually un-blocking without a full file reload or service restart.
func (b *Blocklist) Remove(ip net.IP) {
	if ip == nil {
		return
	}
	ip = normalize(ip)

	b.mu.Lock()
	delete(b.ips, ip.String())
	delete(b.dynamic, ip.String())
	b.mu.Unlock()
}

// FetchAndReload downloads a blocklist file from url and atomically
// replaces the file at path, then reloads it into the Blocklist.
func (b *Blocklist) FetchAndReload(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: unexpected status %s", url, resp.Status)
	}

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("creating temp file %s: %w", tmp, err)
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	f.Close()

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return b.LoadFile(path)
}

// StartAutoRefresh runs FetchAndReload on a ticker, logging errors instead
// of crashing the WAF if a fetch fails (stale data is safer than no data).
func (b *Blocklist) StartAutoRefresh(url, path string, interval time.Duration, logf func(format string, args ...any)) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := b.FetchAndReload(url, path); err != nil {
				logf("waf: auto-refresh failed for %s: %v", url, err)
			}
		}
	}()
}
