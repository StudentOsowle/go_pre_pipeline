package waf

import "strings"

var suspiciousUserAgents = []string{
	"mozilla/4.0 (compatible; msie 6.0; windows nt 5.1)",
	"mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0) like gecko",

	"python-requests",
	"python-urllib",
	"go-http-client",
	"okhttp",
	"libwww-perl",
	"lwp-trivial",

	"curl/7.",
}

func IsSuspiciousUserAgent(ua string) bool {
	if ua == "" {
		return true
	}
	lower := strings.ToLower(ua)
	for _, sig := range suspiciousUserAgents {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

func IsGitClient(ua string) bool {
	return strings.HasPrefix(strings.ToLower(ua), "git/")
}
