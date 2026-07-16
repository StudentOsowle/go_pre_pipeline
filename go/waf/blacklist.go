package waf

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type Blocklist struct {
	mu    sync.RWMutex
	ips   map[string]struct{}
	cidrs []*net.IPNet
}

func NewBlocklist() *Blocklist {
	return &Blocklist{ips: make(map[string]struct{})}
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
				continue
			}
			cidrs = append(cidrs, ipnet)
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			ips[ip.String()] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	b.ips = ips
	b.cidrs = cidrs
	b.mu.Unlock()
	return nil
}

func (b *Blocklist) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
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
	b.mu.Lock()
	b.ips[ip.String()] = struct{}{}
	b.mu.Unlock()
}
