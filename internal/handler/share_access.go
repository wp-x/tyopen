package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
	"tyopen/internal/model"

	"github.com/gin-gonic/gin"
)

// shareAuthCookiePrefix 分享密码免密 cookie 前缀（share_auth_<code>）
const shareAuthCookiePrefix = "share_auth_"

// shareAuthCookieTTL 分享无过期时间时 cookie 的默认有效期
const shareAuthCookieTTL = 24 * time.Hour

// shareTreeCacheTTL 文件夹分享子树 ID 集合缓存有效期
const shareTreeCacheTTL = 30 * time.Second

// shareAuthToken 计算分享免密 cookie 值：HMAC-SHA256(分享密码, JWT secret) 的 hex
func (h *Handler) shareAuthToken(sharePassword string) string {
	mac := hmac.New(sha256.New, []byte(h.jwtSecret))
	mac.Write([]byte(sharePassword))
	return hex.EncodeToString(mac.Sum(nil))
}

// setShareAuthCookie 密码验证成功后写免密 cookie（HttpOnly，过期与分享对齐，无过期则 24h）
func (h *Handler) setShareAuthCookie(c *gin.Context, share *model.Share) {
	maxAge := int(shareAuthCookieTTL.Seconds())
	if share.ExpireAt != nil {
		remain := int(time.Until(*share.ExpireAt).Seconds())
		if remain < maxAge {
			maxAge = remain
		}
	}
	if maxAge < 0 {
		maxAge = 0
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     shareAuthCookiePrefix + share.ShareCode,
		Value:    h.shareAuthToken(share.Password),
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// shareAuthCookieValid 校验分享免密 cookie（常量时间比较）
func (h *Handler) shareAuthCookieValid(c *gin.Context, share *model.Share) bool {
	if share.Password == "" {
		return false
	}
	cookie, err := c.Cookie(shareAuthCookiePrefix + share.ShareCode)
	if err != nil || cookie == "" {
		return false
	}
	want := h.shareAuthToken(share.Password)
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(want)) == 1
}

// sharePasswordGranted 分享密码校验：query pwd 匹配或免密 cookie 匹配，任一通过即放行。
// 通过时重置失败计数；不通过时不写响应（由调用方决定 401/429 写法）。
func (h *Handler) sharePasswordGranted(c *gin.Context, share *model.Share) bool {
	if share.Password == "" {
		return true
	}
	if c.Query("pwd") == share.Password || h.shareAuthCookieValid(c, share) {
		h.resetSharePasswordFailures(c)
		return true
	}
	return false
}

// ===================== 分享子树归属判定（防 IDOR） =====================

type shareTreeCacheEntry struct {
	ids     map[string]bool
	expires time.Time
}

var shareTreeCache = struct {
	sync.Mutex
	m map[string]shareTreeCacheEntry
}{m: make(map[string]shareTreeCacheEntry)}

// shareTreeIDs 枚举分享子树的所有文件/目录 ID（含根），带 30s 缓存
func (h *Handler) shareTreeIDs(share *model.Share) (map[string]bool, error) {
	key := share.ShareCode + "|" + share.TargetID

	shareTreeCache.Lock()
	entry, ok := shareTreeCache.m[key]
	if ok && time.Now().Before(entry.expires) {
		shareTreeCache.Unlock()
		return entry.ids, nil
	}
	shareTreeCache.Unlock()

	ids, err := h.buildShareTreeIDs(share.TargetID)
	if err != nil {
		return nil, err
	}

	shareTreeCache.Lock()
	shareTreeCache.m[key] = shareTreeCacheEntry{ids: ids, expires: time.Now().Add(shareTreeCacheTTL)}
	shareTreeCache.Unlock()
	return ids, nil
}

// buildShareTreeIDs BFS 枚举子树（复用 listAllShareFiles 的分页枚举逻辑）
func (h *Handler) buildShareTreeIDs(rootID string) (map[string]bool, error) {
	ids := map[string]bool{rootID: true}
	queue := []string{rootID}
	for len(queue) > 0 {
		dirID := queue[0]
		queue = queue[1:]
		files, err := h.listAllShareFiles(dirID)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if ids[f.ID] {
				continue
			}
			ids[f.ID] = true
			if f.IsDir {
				queue = append(queue, f.ID)
			}
		}
	}
	return ids, nil
}

// resolveShareFileID 校验 fid/dir_id 归属：
// 单文件分享只能用 target_id；文件夹分享必须是 target_id 或其后代。
// 返回 ("", false) 表示禁止访问（调用方返回 404，不泄露信息）。
func (h *Handler) resolveShareFileID(share *model.Share, fileID string) (string, bool) {
	if fileID == "" || fileID == "0" {
		return share.TargetID, true
	}
	if fileID == share.TargetID {
		return fileID, true
	}
	if share.TargetType != "folder" {
		return "", false
	}
	ids, err := h.shareTreeIDs(share)
	if err != nil {
		return "", false
	}
	if ids[fileID] {
		return fileID, true
	}
	return "", false
}
