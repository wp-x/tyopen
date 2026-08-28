package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestProxyTrust(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		peer  string
		want  bool
	}{
		{name: "empty rejects", input: nil, peer: "127.0.0.1", want: false},
		{name: "bare IPv4", input: []string{"127.0.0.1"}, peer: "127.0.0.1", want: true},
		{name: "CIDR", input: []string{"10.0.0.0/8"}, peer: "10.1.2.3", want: true},
		{name: "outside CIDR", input: []string{"10.0.0.0/8"}, peer: "192.168.1.1", want: false},
		{name: "invalid ignored", input: []string{"not-an-ip"}, peer: "127.0.0.1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newProxyTrust(tt.input).trusted(tt.peer); got != tt.want {
				t.Fatalf("trusted(%q)=%v, want %v", tt.peer, got, tt.want)
			}
		})
	}
}

func TestRequestBaseURLTrustBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	makeContext := func(peer string, headers map[string]string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "real.example"
		req.RemoteAddr = peer + ":1234"
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		c.Request = req
		return c
	}

	forwarded := map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "public.example",
	}
	untrusted := &Handler{proxyTrust: newProxyTrust(nil)}
	if got := untrusted.requestBaseURL(makeContext("203.0.113.5", forwarded)); got != "http://real.example" {
		t.Fatalf("untrusted forwarded headers: got %q", got)
	}

	trusted := &Handler{proxyTrust: newProxyTrust([]string{"203.0.113.5"})}
	if got := trusted.requestBaseURL(makeContext("203.0.113.5", forwarded)); got != "https://public.example" {
		t.Fatalf("trusted forwarded headers: got %q", got)
	}

	configured := &Handler{siteURL: "https://fixed.example/", proxyTrust: newProxyTrust(nil)}
	if got := configured.requestBaseURL(makeContext("203.0.113.5", forwarded)); got != "https://fixed.example" {
		t.Fatalf("configured site URL: got %q", got)
	}
}
