package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config 系统配置
type Config struct {
	Port          string   // 服务端口
	DataDir       string   // 数据目录
	AdminPassword string   // 管理员密码
	JWTSecret     string   // JWT密钥
	SiteURL       string   // 站点URL（为空时按请求动态推导）
	// TrustedProxies 可信反向代理 IP/CIDR 列表。为空=不信任任何代理头：
	// 此时 ClientIP 限流/日志取真实 TCP 对端，X-Forwarded-* 一律忽略。
	// 部署在 nginx/caddy 等反向代理后时必须配置，否则限流会按代理 IP 聚合。
	TrustedProxies []string
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Port:           getEnv("TYOPEN_PORT", "10000"),
		DataDir:        getEnv("TYOPEN_DATA_DIR", "./data"),
		AdminPassword:  getEnv("TYOPEN_ADMIN_PASSWORD", ""),
		JWTSecret:      getEnv("TYOPEN_JWT_SECRET", ""),
		SiteURL:        getEnv("TYOPEN_SITE_URL", ""),
		TrustedProxies: parseCSV(getEnv("TYOPEN_TRUSTED_PROXIES", "")),
	}
}

// parseCSV 把逗号分隔的配置值拆成去空白后的非空列表
func parseCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// DatabasePath 返回数据库文件路径
func (c *Config) DatabasePath() string {
	return filepath.Join(c.DataDir, "tyopen.db")
}

// getEnv 获取环境变量，如果不存在则返回默认值
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
