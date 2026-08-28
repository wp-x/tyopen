package handler

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

func firstHeaderValue(v string) string {
	if v == "" {
		return ""
	}
	// Common reverse-proxy headers can contain multiple values: "https,http".
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// proxyTrust 可信反向代理 CIDR 匹配器（与 gin 的 trustedCIDRs 保持一致，
// gin 的 isTrustedProxy 是私有方法，这里在 handler 内独立维护一份）。
type proxyTrust struct {
	nws []*net.IPNet
}

func newProxyTrust(cidrs []string) *proxyTrust {
	t := &proxyTrust{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// 支持裸 IP（按 32/128 位全匹配）
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			t.nws = append(t.nws, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, nw, err := net.ParseCIDR(c); err == nil {
			t.nws = append(t.nws, nw)
		}
	}
	return t
}

func (t *proxyTrust) trusted(peer string) bool {
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	for _, nw := range t.nws {
		if nw.Contains(ip) {
			return true
		}
	}
	return false
}

// requestBaseURL 构建对外展示/复制用的站点基础 URL（scheme://host）。
// 优先级：显式配置的 TYOPEN_SITE_URL > （仅当请求来自可信代理时）X-Forwarded-* > 请求本身。
// 不信任任何代理时忽略 X-Forwarded-*，防止直接暴露的实例被 Host 投毒。
func (h *Handler) requestBaseURL(c *gin.Context) string {
	if h.siteURL != "" {
		return strings.TrimSuffix(h.siteURL, "/")
	}

	// 仅可信代理的转发头才被采信
	if h.proxyTrust.trusted(c.RemoteIP()) {
		if scheme := firstHeaderValue(c.GetHeader("X-Forwarded-Proto")); scheme != "" {
			if host := firstHeaderValue(c.GetHeader("X-Forwarded-Host")); host != "" {
				return scheme + "://" + host
			}
		}
	}

	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.Request.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host
}
