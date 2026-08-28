package handler

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"tyopen/internal/model"

	"github.com/gin-gonic/gin"
)

const (
	publicShareWindow        = 15 * time.Minute
	publicShareMaxEntries    = 10000
	publicShareMaxIPEntries  = 2048
	publicShareViewLimit     = 120
	publicShareFilesLimit    = 60
	publicShareContentLimit  = 30
	publicShareVerifyLimit   = 30
	publicShareDownloadLimit = 60
)

type publicRateEntry struct {
	count int
}

type publicShareRateLimiter struct {
	mu       sync.Mutex
	window   time.Time
	counts   map[string]publicRateEntry
	ipCounts map[string]publicRateEntry
}

func newPublicShareRateLimiter() *publicShareRateLimiter {
	return &publicShareRateLimiter{
		window:   time.Now(),
		counts:   make(map[string]publicRateEntry),
		ipCounts: make(map[string]publicRateEntry),
	}
}

func publicShareIPLimit(operation string) int {
	switch operation {
	case "files", "download", "preview":
		return 240
	case "content":
		return 120
	case "verify":
		return 60
	default:
		return 600
	}
}

func (l *publicShareRateLimiter) allow(ip, key, operation string, limit int) bool {
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.window) >= publicShareWindow {
		l.window = now
		l.counts = make(map[string]publicRateEntry)
		l.ipCounts = make(map[string]publicRateEntry)
	}
	ipKey := ip + "|" + operation
	ipEntry := l.ipCounts[ipKey]
	if ipEntry.count >= publicShareIPLimit(operation) {
		return false
	}
	keyEntry := l.counts[key]
	if keyEntry.count >= limit {
		return false
	}
	// Evict an arbitrary bucket instead of scanning the whole map. This keeps
	// per-request overhead O(1) while bounding memory against random-key poisoning.
	if _, exists := l.counts[key]; !exists && len(l.counts) >= publicShareMaxEntries {
		evictOnePublicRateEntry(l.counts)
	}
	if _, exists := l.ipCounts[ipKey]; !exists && len(l.ipCounts) >= publicShareMaxIPEntries {
		evictOnePublicRateEntry(l.ipCounts)
	}
	l.counts[key] = publicRateEntry{count: keyEntry.count + 1}
	ipEntry.count++
	l.ipCounts[ipKey] = ipEntry
	return true
}

func evictOnePublicRateEntry(entries map[string]publicRateEntry) {
	for key := range entries {
		delete(entries, key)
		return
	}
}

func (h *Handler) publicClientIP(c *gin.Context) string {
	peer := c.RemoteIP()
	if h.proxyTrust != nil && h.proxyTrust.trusted(peer) {
		if ip := c.ClientIP(); ip != "" {
			return ip
		}
	}
	return peer
}

// AllowPublicShareRequest limits anonymous share endpoints by client IP, share code and operation.
// It is exported for route wrappers that also serve the SPA HTML response.
func (h *Handler) AllowPublicShareRequest(c *gin.Context, operation string) bool {
	code := strings.TrimSpace(c.Param("code"))
	limit := publicShareViewLimit
	switch operation {
	case "files":
		limit = publicShareFilesLimit
	case "content":
		limit = publicShareContentLimit
	case "verify":
		limit = publicShareVerifyLimit
	case "download", "preview":
		limit = publicShareDownloadLimit
	}
	key := h.publicClientIP(c) + "|" + code + "|" + operation
	if h.publicShareLimiter.allow(h.publicClientIP(c), key, operation, limit) {
		return true
	}
	c.Header("Retry-After", "900")
	c.JSON(http.StatusTooManyRequests, model.APIResponse{Code: 429, Message: "请求过于频繁，请稍后再试"})
	return false
}

func (h *Handler) RequirePublicShareRequest(c *gin.Context, operation string) bool {
	if h.AllowPublicShareRequest(c, operation) {
		return true
	}
	c.Abort()
	return false
}
