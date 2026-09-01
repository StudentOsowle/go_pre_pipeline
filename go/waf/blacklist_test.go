package waf

import (
	"net"
	"os"
	"testing"
)

func TestBlocklist_LoadFile_ContainsIP(t *testing.T) {
	tmp, err := os.CreateTemp("", "blocklist-*.txt")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	tmp.WriteString("# comment line\n")
	tmp.WriteString("203.0.113.5\n")
	tmp.WriteString("198.51.100.0/24\n")
	tmp.Close()

	bl := NewBlocklist()
	if err := bl.LoadFile(tmp.Name()); err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if !bl.Contains(net.ParseIP("203.0.113.5")) {
		t.Error("expected exact-match IP to be blocked")
	}
	if !bl.Contains(net.ParseIP("198.51.100.42")) {
		t.Error("expected IP within CIDR range to be blocked")
	}
	if bl.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("expected unrelated IP to NOT be blocked")
	}
}

func TestBlocklist_LoadFile_MissingFileIsNotError(t *testing.T) {
	bl := NewBlocklist()
	if err := bl.LoadFile("this-file-does-not-exist.txt"); err != nil {
		t.Errorf("expected no error for missing file, got: %v", err)
	}
}

func TestBlocklist_Add_And_Remove(t *testing.T) {
	bl := NewBlocklist()
	ip := net.ParseIP("192.0.2.1")

	bl.Add(ip)
	if !bl.Contains(ip) {
		t.Error("expected IP to be blocked after Add")
	}

	bl.Remove(ip)
	if bl.Contains(ip) {
		t.Error("expected IP to NOT be blocked after Remove")
	}
}

func TestBlocklist_DynamicIPs_SurviveReload(t *testing.T) {
	tmp, err := os.CreateTemp("", "blocklist-*.txt")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("203.0.113.5\n")
	tmp.Close()

	bl := NewBlocklist()
	if err := bl.LoadFile(tmp.Name()); err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	dynamicIP := net.ParseIP("192.0.2.99")
	bl.Add(dynamicIP)

	if err := bl.LoadFile(tmp.Name()); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	if !bl.Contains(dynamicIP) {
		t.Error("expected dynamically-added IP to survive a file reload")
	}
}

func TestBlocklist_IPv4MappedIPv6_Normalized(t *testing.T) {
	bl := NewBlocklist()
	bl.Add(net.ParseIP("127.0.0.1"))

	mapped := net.ParseIP("::ffff:127.0.0.1")
	if !bl.Contains(mapped) {
		t.Error("expected IPv4-mapped IPv6 address to match plain IPv4 blocklist entry")
	}
}
