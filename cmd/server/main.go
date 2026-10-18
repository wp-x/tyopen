package main

import (
	"log"

	"tyopen/internal/cloud189"
	"tyopen/internal/config"
	"tyopen/internal/middleware"
	"tyopen/internal/repository"
)

func main() {
	// 加载配置
	cfg := config.DefaultConfig()
	if len(cfg.JWTSecret) < 32 {
		log.Fatal("TYOPEN_JWT_SECRET 未配置或长度不足 32 位")
	}
	logStartup(cfg)

	// 初始化数据库，管理员密码是否必需取决于数据库中是否已有 bcrypt 哈希。
	db, err := repository.NewDatabase(cfg.DatabasePath())
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer db.Close()

	repos := initRepositories(db)
	settings, err := repos.settings.Get()
	if err != nil {
		log.Fatalf("读取系统设置失败: %v", err)
	}
	if settings.AdminPasswordHash == "" && len(cfg.AdminPassword) < 12 {
		log.Fatal("TYOPEN_ADMIN_PASSWORD 未配置或长度不足 12 位（数据库中尚未设置管理员密码）")
	}

	// 设置 JWT 密钥与持久化管理员会话版本。
	middleware.JWTSecret = cfg.JWTSecret
	middleware.SetAdminTokenVersion(settings.AdminTokenVersion)

	panClient := initCloud189Client(repos.settings)
	h := initHandler(repos, panClient, cfg)
	monitorService := initMonitorService(repos, panClient, h)
	maybeStartMonitor(repos.settings, monitorService)

	r := setupRouter(routeOptions{
		handler: h,
	}, cfg)
	davHandler := newWebDAVHandler(panClient, repos.settings, h.VerifyAdminPassword)
	startHTTPServer(r, davHandler, cfg.Port)
}

// initCloud189Client 初始化电信云盘客户端
func initCloud189Client(settingsRepo *repository.SettingsRepository) *cloud189.Client {
	settings, err := settingsRepo.Get()
	if err != nil {
		log.Printf("获取设置失败: %v", err)
		return cloud189.NewClient("", "")
	}

	if settings.Cookie == "" && (settings.Account == "" || settings.Password == "") {
		log.Println("未配置电信云盘凭据（Cookie 或账号密码），请在管理后台配置")
		return cloud189.NewClient("", "")
	}

	client := cloud189.NewClient(settings.Account, settings.Password)
	client.SetRootFolderID(settings.RootFolderID)

	// 设置了 Cookie 时优先使用 Cookie 会话模式
	if settings.Cookie != "" {
		client.SetCookie(settings.Cookie)
		log.Println("使用 Cookie 会话模式连接天翼云盘")
	}

	// 用库里存的 token 预热，Init 时优先用 refreshToken 换 session
	if settings.RefreshToken != "" || settings.AccessToken != "" {
		client.SetTokens(settings.RefreshToken, settings.AccessToken)
	}

	// 设置Token更新回调
	client.SetTokenUpdateCallback(func(refreshToken, accessToken string) {
		if err := settingsRepo.UpdateToken(refreshToken, accessToken); err != nil {
			log.Printf("保存Token失败: %v", err)
		} else {
			log.Println("Token已自动更新并保存")
		}
	})

	// 初始化客户端（个人云模式）
	if err := client.Init(); err != nil {
		log.Printf("初始化云盘客户端失败: %v (请检查账号密码是否正确)", err)
		return client
	}

	// 启动后台保活：PC 模式主动续期 session，Cookie 模式做失效探测
	client.StartKeepAlive(0)

	log.Println("云盘客户端初始化成功")
	return client
}
