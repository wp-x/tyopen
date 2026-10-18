// Package cloud189 实现电信天翼云盘（cloud.189.cn，个人云）客户端。
// 协议依据：项目根目录《电信网盘的参数文档.md》（源自 OpenList drivers/189pc）。
package cloud189

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"
)

const (
	accountType = "02"
	appID       = "8025431004"
	clientType  = "10020"
	version     = "6.2"

	webURL    = "https://cloud.189.cn"
	authURL   = "https://open.e.189.cn"
	apiURL    = "https://api.cloud.189.cn"
	uploadURL = "https://upload.cloud.189.cn"

	returnURL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"

	pcClient  = "TELEPC"
	channelID = "web_cloud.189.cn"

	defaultRootFolderID = "-11" // 个人云根目录 ID

	// syncDiskVirtualID 同步盘虚拟 ID。
	// 天翼云在个人云根目录列表中返回「同步盘」条目 id=0（特殊标记，非真实目录 ID），
	// 上游对 folderId=0 的请求会返回同步盘内容（已实测）。
	// 但本服务内部约定 "0"=根目录（前端/WebDAV 多处依赖），故列表中把该条目
	// 改写为虚拟 ID "-101"，请求侧在 normalizeDirID 中翻译回 "0" 发给上游。
	syncDiskVirtualID = "-101"
)

// errSessionInvalid 表示会话（sessionKey）失效，需要刷新 session 后重试。
var errSessionInvalid = errors.New("session invalid")

// errInvalidOpenToken 表示 accessToken 失效（res_code=UserInvalidOpenToken）。
var errInvalidOpenToken = errors.New("UserInvalidOpenToken")

// Client 电信天翼云盘客户端
type Client struct {
	account  string
	password string

	mu            sync.RWMutex // 保护以下字段
	cookie        string
	rootFolderID  string
	accessToken   string
	refreshToken  string
	sessionKey    string
	sessionSecret string
	initialized   bool
	onTokenUpdate func(refreshToken, accessToken string)

	// keepAliveCancel 终止后台保活 goroutine；keepAliveOnce 保证只启动一次
	keepAliveCancel context.CancelFunc
	keepAliveOnce   sync.Once

	// sessionMu 串行化 session/token 刷新与完整登录，防止并发重复刷新。
	sessionMu sync.Mutex
	// pendingMu 保护二次校验暂存上下文
	pendingMu sync.Mutex
	pending   *pendingLogin

	httpClient *http.Client // 带 cookie jar，登录流程依赖会话 cookie

	pc  *pcBackend
	web *webBackend
}

// newCloudHTTPClient 为云盘 API/上传请求提供连接层超时和整体超时。
// 上传按分片执行，单片 2 分钟足够宽松；整体上传仍由调用方 context 控制。
func newCloudHTTPClient(jar http.CookieJar) *http.Client {
	return &http.Client{
		Jar:     jar,
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
	}
}

// NewClient 创建电信云盘客户端（账号为手机号）
func NewClient(account, password string) *Client {
	jar, _ := cookiejar.New(nil)
	c := &Client{
		account:    account,
		password:   password,
		httpClient: newCloudHTTPClient(jar),
	}
	c.pc = &pcBackend{c: c}
	c.web = newWebBackend(c)
	return c
}

// SetCookie 设置网页版 Cookie（设置了 Cookie 时优先使用 Cookie 会话模式）
func (c *Client) SetCookie(cookie string) {
	c.mu.Lock()
	c.cookie = cookie
	c.mu.Unlock()
}

func (c *Client) getCookie() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cookie
}

// activeBackend 按凭据类型分派后端模式：有 Cookie 用网页版 API，否则 PC 协议
func (c *Client) activeBackend() panBackend {
	if c.getCookie() != "" {
		return c.web
	}
	return c.pc
}

// SetTokenUpdateCallback 设置 Token 更新回调（登录/刷新后落库）
func (c *Client) SetTokenUpdateCallback(callback func(refreshToken, accessToken string)) {
	c.mu.Lock()
	c.onTokenUpdate = callback
	c.mu.Unlock()
}

// SetRootFolderID 设置根文件夹 ID，空则使用默认 "-11"
func (c *Client) SetRootFolderID(id string) {
	c.mu.Lock()
	c.rootFolderID = id
	c.mu.Unlock()
}

// SetTokens 用库里存的 token 预热，Init 时优先用 refreshToken 换 session
func (c *Client) SetTokens(refreshToken, accessToken string) {
	c.mu.Lock()
	c.refreshToken = refreshToken
	c.accessToken = accessToken
	c.mu.Unlock()
}

// Init 建立会话：设置了 Cookie 时进入 Cookie 会话模式（网页版 API）；
// 否则走 PC 协议：优先 refreshToken 换 session，失败回退密码登录
func (c *Client) Init() error {
	if err := c.activeBackend().init(context.Background()); err != nil {
		return err
	}
	c.mu.Lock()
	c.initialized = true
	c.mu.Unlock()
	return nil
}

// IsInitialized 检查客户端是否已初始化
func (c *Client) IsInitialized() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cookie != "" {
		return c.initialized
	}
	return c.initialized && c.sessionKey != ""
}

// GetRefreshToken 获取当前的 RefreshToken
func (c *Client) GetRefreshToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.refreshToken
}

// GetAccessToken 获取当前的 AccessToken
func (c *Client) GetAccessToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken
}

func (c *Client) getRootFolderID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rootFolderID == "" || c.rootFolderID == "0" {
		return defaultRootFolderID
	}
	return c.rootFolderID
}

// normalizeDirID 把 ""/"0" 映射为根目录 ID；同步盘虚拟 ID 翻译回上游的 0
func (c *Client) normalizeDirID(dirID string) string {
	if dirID == syncDiskVirtualID {
		return "0" // 上游 folderId=0 = 同步盘根
	}
	if dirID == "" || dirID == "0" {
		return c.getRootFolderID()
	}
	return dirID
}

func (c *Client) getSession() (sessionKey, sessionSecret string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionKey, c.sessionSecret
}

func (c *Client) getTokens() (accessToken, refreshToken string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken, c.refreshToken
}

// setSession 写入 session 与 token，并按需触发 token 更新回调
func (c *Client) setSession(sessionKey, sessionSecret, accessToken, refreshToken string) {
	c.mu.Lock()
	if sessionKey != "" {
		c.sessionKey = sessionKey
	}
	if sessionSecret != "" {
		c.sessionSecret = sessionSecret
	}
	tokenChanged := false
	if accessToken != "" && accessToken != c.accessToken {
		c.accessToken = accessToken
		tokenChanged = true
	}
	if refreshToken != "" && refreshToken != c.refreshToken {
		c.refreshToken = refreshToken
		tokenChanged = true
	}
	callback := c.onTokenUpdate
	rt, at := c.refreshToken, c.accessToken
	c.mu.Unlock()

	if tokenChanged && callback != nil {
		callback(rt, at)
	}
}

// ensureSession 确保有可用 session（request 模板入口调用）
func (c *Client) ensureSession(ctx context.Context) error {
	sessionKey, _ := c.getSession()
	if sessionKey != "" {
		return nil
	}
	return c.refreshSession(ctx)
}

// refreshSession 刷新会话：优先 accessToken 换 session；token 失效则 refreshToken
// 换新 token 再换 session；都失败回退完整密码登录。
func (c *Client) refreshSession(ctx context.Context) error {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	accessToken, _ := c.getTokens()
	if accessToken != "" {
		err := c.getSessionByToken(ctx)
		if err == nil {
			return nil
		}
		if errors.Is(err, errInvalidOpenToken) {
			if refreshErr := c.refreshTokenLocked(ctx); refreshErr == nil {
				if sessionErr := c.getSessionByToken(ctx); sessionErr == nil {
					return nil
				}
			}
		}
		// token 路径走不通，回退密码登录
	}
	return c.loginLocked(ctx)
}

// requireInitialized 供业务方法调用前检查
func (c *Client) requireInitialized() error {
	if !c.IsInitialized() {
		return fmt.Errorf("云盘客户端未初始化")
	}
	return nil
}

// StartKeepAlive 启动后台保活：PC 协议模式定期调用 keepUserSession.action 心跳维持
// 会话（对齐 OpenList 189pc 的 keepAlive），心跳失败再立即 refreshSession；Cookie 模式
// 无服务端续期能力，改为轻量有效性探测并在失效时告警。重复调用只生效一次。
// 仅在常驻客户端创建点（initCloud189Client / reinitPanClient）显式调用，
// 临时校验客户端不应启动以免留下孤儿 goroutine。
func (c *Client) StartKeepAlive(interval time.Duration) {
	c.keepAliveOnce.Do(func() {
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		ctx, cancel := context.WithCancel(context.Background())
		c.keepAliveCancel = cancel
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					c.keepAliveTick(ctx)
				}
			}
		}()
	})
}

// keepAliveTick 单次保活动作（对齐 OpenList 189pc：先 keepUserSession 心跳，
// 心跳失败再立即 refreshSession；request() 内部另含 3 次刷新重试作为兜底）。
func (c *Client) keepAliveTick(ctx context.Context) {
	if !c.IsInitialized() {
		return
	}
	if c.getCookie() != "" {
		// Cookie 模式无服务端续期，仅探测失效并告警，避免静默失败
		if _, err := c.web.listFiles(ctx, defaultRootFolderID, 1, 1); err != nil {
			if errors.Is(err, errCookieInvalid) {
				log.Printf("[cloud189] 网页版 Cookie 已失效，请在管理后台重新填写 Cookie 以恢复访问")
			}
		}
		return
	}
	// PC 协议模式：调用 keepUserSession.action 维持会话活跃（轻量心跳，不换 sessionKey）。
	// 失败（多为会话失效）立即尝试刷新，而非等下一周期——这正是 OpenList 不掉线的关键。
	if err := c.keepUserSession(ctx); err != nil {
		if errors.Is(err, errNeedSecondAuth) {
			// 短信二次校验无法自动完成，停止保活避免持续刷错误日志
			log.Printf("[cloud189] 保活刷新需要短信二次校验，无法自动续期，已停止保活（请关闭设备锁或重新配置）")
			c.StopKeepAlive()
			return
		}
		log.Printf("[cloud189] 会话心跳失败，尝试刷新会话: %v", err)
		if refreshErr := c.refreshSession(ctx); refreshErr != nil {
			log.Printf("[cloud189] 保活刷新失败，将在下次周期重试: %v", refreshErr)
		}
	}
}

// keepUserSession 调用 keepUserSession.action 维持会话活跃（对齐 OpenList 189pc 的
// keepAlive）。直接走签名请求模板（不进 request() 重试循环，保活本身是兜底），
// 仅识别会话失效信号以触发上层刷新。
func (c *Client) keepUserSession(ctx context.Context) error {
	body, err := c.doSignedRequest(ctx, http.MethodGet, apiURL+"/keepUserSession.action", nil, nil, nil)
	if err != nil {
		// doSignedRequest 已把 401/403、缺失 session 转成 errSessionInvalid
		return err
	}
	if e := isSessionExpiredBody(body); e != nil {
		return e
	}
	return nil
}

// StopKeepAlive 停止后台保活（客户端被替换时调用，避免孤儿 goroutine）。
func (c *Client) StopKeepAlive() {
	if c.keepAliveCancel != nil {
		c.keepAliveCancel()
	}
}
