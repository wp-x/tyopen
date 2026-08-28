package config

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Config 系统配置
type Config struct {
	Port           string   // 服务端口
	DataDir        string   // 数据目录
	AdminPassword  string   // 管理员密码
	JWTSecret      string   // JWT密钥
	SiteURL        string   // 站点URL（为空时按请求动态推导）
	TrustedProxies []string // 可信反向代理 IP/CIDR，空值表示不信任代理头
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	port := getEnv("TYOPEN_PORT", "10000")
	return &Config{
		Port:          port,
		DataDir:       getEnv("TYOPEN_DATA_DIR", "./data"),
		AdminPassword: getEnv("TYOPEN_ADMIN_PASSWORD", ""),
		JWTSecret:     getEnv("TYOPEN_JWT_SECRET", ""),
		// 未配置外部地址时固定为本地地址，避免直接暴露实例根据任意 Host 头生成投毒链接。
		// 通过反代访问时请显式设置 TYOPEN_SITE_URL，或配置可信代理后使用转发头。
		SiteURL:        getEnv("TYOPEN_SITE_URL", "http://localhost:"+port),
		TrustedProxies: parseTrustedProxies(getEnv("TYOPEN_TRUSTED_PROXIES", "")),
	}
}

func parseTrustedProxies(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			if _, _, err := net.ParseCIDR(item); err != nil {
				continue
			}
		} else if net.ParseIP(item) == nil {
			continue
		}
		values = append(values, item)
	}
	return values
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
