package handler

import (
	"net"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func firstHeaderValue(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

type proxyTrust struct {
	nets []*net.IPNet
}

func newProxyTrust(values []string) *proxyTrust {
	trust := &proxyTrust{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				ip = ipv4
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			trust.nets = append(trust.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, network, err := net.ParseCIDR(value); err == nil {
			trust.nets = append(trust.nets, network)
		}
	}
	return trust
}

func (p *proxyTrust) trusted(peer string) bool {
	if p == nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(peer))
	if ip == nil {
		return false
	}
	for _, network := range p.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// requestBaseURL 构建对外展示/复制用的站点基础 URL。
// 显式 TYOPEN_SITE_URL 优先；只有 TCP 对端是可信代理时才采信转发头。
func (h *Handler) requestBaseURL(c *gin.Context) string {
	if siteURL := normalizeSiteURL(h.siteURL); siteURL != "" {
		return siteURL
	}

	if h.proxyTrust.trusted(c.RemoteIP()) {
		scheme := firstHeaderValue(c.GetHeader("X-Forwarded-Proto"))
		host := firstHeaderValue(c.GetHeader("X-Forwarded-Host"))
		if isHTTPOrHTTPS(scheme) && validHostHeader(host) {
			return strings.ToLower(scheme) + "://" + host
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

func normalizeSiteURL(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), "/")
	if value == "" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil || !isHTTPOrHTTPS(u.Scheme) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return value
}

func isHTTPOrHTTPS(scheme string) bool {
	return strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")
}

func validHostHeader(host string) bool {
	if host == "" || strings.ContainsAny(host, "\r\n/@ \t") {
		return false
	}
	return true
}
