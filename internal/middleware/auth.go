package middleware

import (
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims JWT声明
// TokenVersion 与数据库中的管理员会话版本绑定；改密/登出后递增版本，
// 使旧的管理 API Token 和 WebDAV Bearer Token 同时失效。
type JWTClaims struct {
	jwt.RegisteredClaims
	TokenVersion int64 `json:"ver"`
}

// JWTSecret JWT密钥（运行时设置）
var JWTSecret string

var adminTokenVersion atomic.Int64

// SetAdminTokenVersion 设置当前管理员会话版本（启动从 SQLite 加载）。
func SetAdminTokenVersion(version int64) {
	if version < 0 {
		version = 0
	}
	adminTokenVersion.Store(version)
}

// AdminTokenVersion 获取当前管理员会话版本。
func AdminTokenVersion() int64 {
	return adminTokenVersion.Load()
}

// AdvanceAdminTokenVersion 单调提升管理员会话版本，避免并发登出/改密完成顺序
// 与事务提交顺序不一致时，内存版本被较小值覆盖。
func AdvanceAdminTokenVersion(version int64) {
	if version < 0 {
		return
	}
	for current := adminTokenVersion.Load(); version > current; current = adminTokenVersion.Load() {
		if adminTokenVersion.CompareAndSwap(current, version) {
			return
		}
	}
}

// GenerateToken 生成JWT Token，expire: 7d | 30d | forever（默认30d）
func GenerateToken(expire string) (string, error) {
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
			Issuer:   "tyopen",
		},
		TokenVersion: AdminTokenVersion(),
	}
	// ponytail: forever 即不设过期；JWT 的服务端版本仍可使其失效。
	switch expire {
	case "7d":
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour))
	case "forever":
	default:
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour))
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(JWTSecret))
}

// ValidateToken 验证JWT Token，包括签名、标准声明和服务端会话版本。
func ValidateToken(tokenString string) bool {
	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return false
	}
	return claims.TokenVersion == AdminTokenVersion()
}

// AuthMiddleware JWT认证中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从Header获取Token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "未授权访问",
			})
			c.Abort()
			return
		}

		// 解析Bearer Token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "授权格式错误",
			})
			c.Abort()
			return
		}

		// 验证Token
		if !ValidateToken(parts[1]) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    401,
				"message": "Token无效或已过期",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CORSMiddleware CORS中间件
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SecurityHeadersMiddleware 为公开和管理端响应统一增加基础安全头。
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		// 应用本身只在 TLS 连接上设置 HSTS；TLS 终止在反代时由反代负责 HSTS，
		// 避免直接暴露实例被伪造 X-Forwarded-Proto 后错误发送安全策略。
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}
