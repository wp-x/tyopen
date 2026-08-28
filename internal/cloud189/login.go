package cloud189

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// errNeedSecondAuth 账号需要短信二次校验（loginSubmit result=-133），
// 非交互登录路径（Init）遇到时返回该错误，引导走 StartLogin/SubmitLoginSMS。
var errNeedSecondAuth = errors.New("账号需要短信二次校验，请通过登录接口完成验证")

// appSessionResp getSessionForPC 响应
type appSessionResp struct {
	ResCode    json.RawMessage `json:"res_code"`
	ResMessage string          `json:"res_message"`
	LoginName  string          `json:"loginName"`
	KeepAlive  int             `json:"keepAlive"`

	SessionKey    string `json:"sessionKey"`
	SessionSecret string `json:"sessionSecret"`

	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

var (
	captchaTokenRe = regexp.MustCompile(`'captchaToken' value='(.+?)'`)
	ltRe           = regexp.MustCompile(`lt = "(.+?)"`)
	paramIDRe      = regexp.MustCompile(`paramId = "(.+?)"`)
	reqIDRe        = regexp.MustCompile(`reqId = "(.+?)"`)
)

// loginContext 一次登录流程的暂存上下文：从取登录页参数 → loginSubmit →
// 二次校验 → getSessionForPC 必须共用同一套参数与同一个 cookie jar（c.httpClient）。
type loginContext struct {
	c *Client

	captchaToken string
	lt           string
	paramID      string
	reqID        string
	pre          string
	pubKeyPEM    string
	rsaUsername  string
	rsaPassword  string
}

// loginSubmitResp loginSubmit.do 响应（含二次校验分支字段）
type loginSubmitResp struct {
	Msg    string `json:"msg"`
	Result int    `json:"result"`
	ToURL  string `json:"toUrl"`

	// result=-134（密码二次校验）：带 apToken 原样重提
	ApToken string `json:"apToken"`
	// result=-133（短信二次校验）
	Mobile         string `json:"mobile"`
	ShowName       string `json:"showName"`
	IsSystem       any    `json:"isSystem"`       // 上游可能返回数字或字符串，不使用
	RomaSecondAuth any    `json:"romaSecondAuth"` // 上游可能返回布尔或字符串
}

// romaSecondAuthEnabled 兼容布尔/字符串两种 JSON 形式
func romaSecondAuthEnabled(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}

// prepareLogin 登录第 1~3 步：取登录页参数 → 取 RSA 公钥加密用户名密码 → 验证码检查
func (c *Client) prepareLogin(ctx context.Context) (*loginContext, error) {
	if c.account == "" || c.password == "" {
		return nil, fmt.Errorf("未配置电信云盘账号或密码，无法登录")
	}
	lc := &loginContext{c: c}

	// 步骤 1 — 取登录页面参数（cookie jar 保存会话 cookie）
	q := url.Values{}
	q.Set("appId", appID)
	q.Set("clientType", clientType)
	q.Set("returnURL", returnURL)
	q.Set("timeStamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
	page, err := c.doPlain(ctx, http.MethodGet, webURL+"/api/portal/unifyLoginForPC.action?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, fmt.Errorf("获取登录页面失败: %w", err)
	}
	lc.captchaToken = regexpSubmatch(captchaTokenRe, page)
	lc.lt = regexpSubmatch(ltRe, page)
	lc.paramID = regexpSubmatch(paramIDRe, page)
	lc.reqID = regexpSubmatch(reqIDRe, page)

	// 步骤 2 — 取 RSA 公钥并加密用户名/密码
	encBody, err := c.doPlain(ctx, http.MethodPost, authURL+"/api/logbox/config/encryptConf.do",
		url.Values{"appId": {appID}}, nil)
	if err != nil {
		return nil, fmt.Errorf("获取 RSA 公钥失败: %w", err)
	}
	var encConf struct {
		Result int `json:"result"`
		Data   struct {
			Pre    string `json:"pre"`
			PubKey string `json:"pubKey"`
		} `json:"data"`
	}
	if err := json.Unmarshal(encBody, &encConf); err != nil {
		return nil, fmt.Errorf("解析 RSA 公钥响应失败: %w", err)
	}
	if encConf.Data.PubKey == "" {
		return nil, fmt.Errorf("获取 RSA 公钥失败: 响应缺少 pubKey")
	}
	lc.pre = encConf.Data.Pre
	lc.pubKeyPEM = "-----BEGIN PUBLIC KEY-----\n" + encConf.Data.PubKey + "\n-----END PUBLIC KEY-----"
	encUsername, err := rsaEncrypt(lc.pubKeyPEM, c.account)
	if err != nil {
		return nil, err
	}
	encPassword, err := rsaEncrypt(lc.pubKeyPEM, c.password)
	if err != nil {
		return nil, err
	}
	lc.rsaUsername = lc.pre + encUsername
	lc.rsaPassword = lc.pre + encPassword

	// 步骤 3 — 验证码检查
	captchaBody, err := c.doPlain(ctx, http.MethodPost, authURL+"/api/logbox/oauth2/needcaptcha.do",
		url.Values{
			"appKey":      {appID},
			"accountType": {accountType},
			"userName":    {lc.rsaUsername},
		}, map[string]string{"REQID": lc.reqID})
	if err != nil {
		return nil, fmt.Errorf("验证码检查失败: %w", err)
	}
	// 响应形如 "0"（带引号）：先 TrimSpace 再 Trim 引号
	if strings.Trim(strings.TrimSpace(string(captchaBody)), `"`) != "0" {
		return nil, fmt.Errorf("账号触发了电信验证码，请稍后再试或在电信官方客户端登录一次")
	}
	return lc, nil
}

// submit 登录第 4 步：提交 loginSubmit.do；apToken 非空时为 -134 分支的原样重提
func (lc *loginContext) submit(ctx context.Context, apToken string) (*loginSubmitResp, error) {
	form := url.Values{
		"appKey":       {appID},
		"accountType":  {accountType},
		"userName":     {lc.rsaUsername},
		"password":     {lc.rsaPassword},
		"validateCode": {""},
		"captchaToken": {lc.captchaToken},
		"returnUrl":    {returnURL},
		"dynamicCheck": {"FALSE"},
		"clientType":   {clientType},
		"cb_SaveName":  {"1"},
		"isOauth2":     {"false"},
		"state":        {""},
		"paramId":      {lc.paramID},
	}
	if apToken != "" {
		form.Set("apToken", apToken)
	}
	loginBody, err := lc.c.doPlain(ctx, http.MethodPost, authURL+"/api/logbox/oauth2/loginSubmit.do",
		form, map[string]string{"REQID": lc.reqID, "lt": lc.lt})
	if err != nil {
		return nil, fmt.Errorf("提交登录失败: %w", err)
	}
	var resp loginSubmitResp
	if err := json.Unmarshal(loginBody, &resp); err != nil {
		return nil, fmt.Errorf("解析登录响应失败: %w", err)
	}
	return &resp, nil
}

// getSession 登录第 5 步：用 toUrl 换 Session
func (lc *loginContext) getSession(ctx context.Context, toURL string) error {
	suffix := url.Values{}
	for k, v := range clientSuffix() {
		suffix.Set(k, v)
	}
	suffix.Set("redirectURL", toURL)
	sessionBody, err := lc.c.doPlain(ctx, http.MethodPost, apiURL+"/getSessionForPC.action?"+suffix.Encode(), nil, nil)
	if err != nil {
		return fmt.Errorf("换取会话失败: %w", err)
	}
	return lc.c.applySessionResponse(sessionBody, "登录换取会话失败")
}

// loginSubmitToSession 处理 loginSubmit 结果：-134 自动带 apToken 重提一次，
// -133 返回 errNeedSecondAuth（由调用方决定交互或报错），成功后换 session。
// 返回 (二次校验响应, 错误)：仅当 result=-133 时第一个返回值非 nil。
func (lc *loginContext) loginSubmitToSession(ctx context.Context) (*loginSubmitResp, error) {
	resp, err := lc.submit(ctx, "")
	if err != nil {
		return nil, err
	}
	if resp.Result == -134 && resp.ApToken != "" {
		// 密码二次校验：把 apToken 加进表单原样重提一次
		if resp, err = lc.submit(ctx, resp.ApToken); err != nil {
			return nil, err
		}
	}
	if resp.Result == -133 {
		return resp, nil
	}
	if resp.ToURL == "" {
		msg := resp.Msg
		if msg == "" {
			msg = "登录失败（响应缺少 toUrl）"
		}
		return nil, fmt.Errorf("电信云盘登录失败: %s", msg)
	}
	return nil, lc.getSession(ctx, resp.ToURL)
}

// loginLocked 完整密码登录流程（非交互），调用方需持有 sessionMu。
// 遇到短信二次校验（-133）时返回 errNeedSecondAuth，不静默失败。
func (c *Client) loginLocked(ctx context.Context) error {
	lc, err := c.prepareLogin(ctx)
	if err != nil {
		return err
	}
	secondAuth, err := lc.loginSubmitToSession(ctx)
	if secondAuth != nil {
		return errNeedSecondAuth
	}
	return err
}

// getSessionByToken 用 accessToken 换 session（Session 刷新），调用方需持有 sessionMu
func (c *Client) getSessionByToken(ctx context.Context) error {
	accessToken, _ := c.getTokens()
	if accessToken == "" {
		return fmt.Errorf("无可用 accessToken")
	}
	suffix := url.Values{}
	for k, v := range clientSuffix() {
		suffix.Set(k, v)
	}
	suffix.Set("appId", appID)
	suffix.Set("accessToken", accessToken)
	body, err := c.doPlain(ctx, http.MethodGet, apiURL+"/getSessionForPC.action?"+suffix.Encode(), nil,
		map[string]string{"X-Request-ID": newUUID()})
	if err != nil {
		return err
	}
	return c.applySessionResponse(body, "刷新会话失败")
}

func (c *Client) applySessionResponse(body []byte, errPrefix string) error {
	if strings.Contains(string(body), "UserInvalidOpenToken") {
		return errInvalidOpenToken
	}
	var resp appSessionResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("%s: 解析响应失败: %w", errPrefix, err)
	}
	if code := rawJSONString(resp.ResCode); code != "" && code != "0" {
		return fmt.Errorf("%s: res_code=%s, res_message=%s", errPrefix, code, resp.ResMessage)
	}
	if resp.SessionKey == "" || resp.SessionSecret == "" {
		return fmt.Errorf("%s: 响应缺少 sessionKey/sessionSecret", errPrefix)
	}
	c.setSession(resp.SessionKey, resp.SessionSecret, resp.AccessToken, resp.RefreshToken)
	return nil
}

// refreshTokenResp refreshToken.do 响应
type refreshTokenResp struct {
	ExpiresIn    int64  `json:"expiresIn"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// refreshTokenLocked 用 refreshToken 换新 accessToken/refreshToken，调用方需持有 sessionMu
func (c *Client) refreshTokenLocked(ctx context.Context) error {
	_, refreshToken := c.getTokens()
	if refreshToken == "" {
		return fmt.Errorf("无可用 refreshToken")
	}
	body, err := c.doPlain(ctx, http.MethodPost, authURL+"/api/oauth2/refreshToken.do",
		url.Values{
			"clientId":     {appID},
			"refreshToken": {refreshToken},
			"grantType":    {"refresh_token"},
			"format":       {"json"},
		}, nil)
	if err != nil {
		return fmt.Errorf("刷新Token失败: %w", err)
	}
	var resp refreshTokenResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("解析刷新Token响应失败: %w", err)
	}
	if resp.AccessToken == "" {
		return fmt.Errorf("刷新Token失败: 响应缺少 accessToken")
	}
	c.setSession("", "", resp.AccessToken, resp.RefreshToken)
	return nil
}

// doPlain 无签名请求（登录/刷新链路使用），form 非空时按表单 POST
func (c *Client) doPlain(ctx context.Context, method, fullURL string, form url.Values, headers map[string]string) ([]byte, error) {
	var bodyReader io.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	req.Header.Set("Referer", webURL)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func regexpSubmatch(re *regexp.Regexp, body []byte) string {
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}
