package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowlistGuard_BlocksUnknownDestination(t *testing.T) {
	var violations []string

	guard := &AllowlistGuard{
		Allowlist:  []string{"raw.githubusercontent.com", "hooks.slack.com"},
		Violations: &violations,
	}

	client := &http.Client{Transport: guard}

	// Legitimate destination — should succeed (or at least not be blocked
	// by the guard; a real network failure is a separate concern here).
	_, _ = client.Get("https://raw.githubusercontent.com/some/test/path")
	if len(violations) != 0 {
		t.Errorf("expected no violations for allowlisted host, got: %v", violations)
	}

	// Unauthorized destination — should be blocked and recorded.
	_, err := client.Get("https://evil-exfil-site.example.com/steal")
	if err == nil {
		t.Error("expected request to unauthorized host to be blocked")
	}
	if len(violations) != 1 || violations[0] != "evil-exfil-site.example.com" {
		t.Errorf("expected one violation for evil-exfil-site.example.com, got: %v", violations)
	}
}

func TestAllowlistGuard_AllowsExplicitPort(t *testing.T) {
	var violations []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	guard := &AllowlistGuard{
		Allowlist:  []string{server.Listener.Addr().String()},
		Violations: &violations,
	}
	client := &http.Client{Transport: guard}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("expected allowlisted local server request to succeed, got error: %v", err)
	}
	resp.Body.Close()

	if len(violations) != 0 {
		t.Errorf("expected no violations, got: %v", violations)
	}
}
