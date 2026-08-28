// Package cloud189 实现电信天翼云盘（cloud.189.cn，个人云）客户端。
// 协议依据：项目根目录《电信网盘的参数文档.md》（源自 OpenList drivers/189pc）。
package cloud189

import (
	"context"
	"errors"
	"fmt"
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

// normalizeDirID 把 ""/"0" 映射为根目录 ID
func (c *Client) normalizeDirID(dirID string) string {
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
