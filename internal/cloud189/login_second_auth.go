package cloud189

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LoginChallenge 短信二次校验挑战（loginSubmit result=-133）。
// Mobile 为服务端返回的脱敏手机号，可直接透传展示。
type LoginChallenge struct {
	Ticket   string `json:"ticket"`
	Mobile   string `json:"mobile"`
	ShowName string `json:"show_name"`
}

// pendingLoginTTL 二次校验上下文有效期
const pendingLoginTTL = 10 * time.Minute

// pendingLogin 暂存的二次校验登录上下文
type pendingLogin struct {
	ticket         string
	expires        time.Time
	lc             *loginContext
	mobile         string
	romaSecondAuth bool
}

// StartLogin 交互式登录：走完整 loginByPassword；若 -134 自动带 apToken 重提；
// 若 -133 自动发送短信验证码并暂存登录上下文（10 分钟有效），返回 challenge；
// 直接成功则返回 nil challenge，此时 session 已建立、Client 可直接使用。
func (c *Client) StartLogin(ctx context.Context) (*LoginChallenge, error) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	lc, err := c.prepareLogin(ctx)
	if err != nil {
		return nil, err
	}
	secondAuth, err := lc.loginSubmitToSession(ctx)
	if err != nil {
		return nil, err
	}
	if secondAuth == nil {
		// 直接登录成功
		c.mu.Lock()
		c.initialized = true
		c.mu.Unlock()
		return nil, nil
	}

	// -133 短信二次校验：发码并暂存上下文
	if secondAuth.Mobile == "" {
		return nil, fmt.Errorf("账号需要短信二次校验，但响应缺少手机号信息")
	}
	if err := lc.sendSmsCodeForSecondAuth(ctx, secondAuth.Mobile); err != nil {
		return nil, err
	}

	ticket := newUUID()
	c.pendingMu.Lock()
	c.pending = &pendingLogin{
		ticket:         ticket,
		expires:        time.Now().Add(pendingLoginTTL),
		lc:             lc,
		mobile:         secondAuth.Mobile,
		romaSecondAuth: romaSecondAuthEnabled(secondAuth.RomaSecondAuth),
	}
	c.pendingMu.Unlock()

	return &LoginChallenge{
		Ticket:   ticket,
		Mobile:   secondAuth.Mobile,
		ShowName: secondAuth.ShowName,
	}, nil
}

// SubmitLoginSMS 提交短信验证码完成二次校验登录
func (c *Client) SubmitLoginSMS(ctx context.Context, ticket, smsCode string) error {
	c.pendingMu.Lock()
	pending := c.pending
	c.pendingMu.Unlock()

	if pending == nil || pending.ticket != ticket || time.Now().After(pending.expires) {
		return fmt.Errorf("验证会话已过期，请重新发起登录")
	}
	if strings.TrimSpace(smsCode) == "" {
		return fmt.Errorf("请输入短信验证码")
	}

	toURL, err := pending.lc.submitForSecondAuth(ctx, pending.mobile, pending.romaSecondAuth, smsCode)
	if err != nil {
		return err
	}

	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if err := pending.lc.getSession(ctx, toURL); err != nil {
		return err
	}

	c.pendingMu.Lock()
	if c.pending == pending {
		c.pending = nil
	}
	c.pendingMu.Unlock()
	c.mu.Lock()
	c.initialized = true
	c.mu.Unlock()
	return nil
}

// sendSmsCodeForSecondAuth 发送二次校验短信验证码
// 错误码：20104/51129=24小时内发码过多，20107=手机号无效，-10320=不支持短信验证
func (lc *loginContext) sendSmsCodeForSecondAuth(ctx context.Context, mobile string) error {
	body, err := lc.c.doPlain(ctx, http.MethodPost, authURL+"/api/logbox/oauth2/sendSmsCodeForSecondAuth.do",
		url.Values{
			"mobile": {mobile},
			"appKey": {appID},
		}, map[string]string{"lt": lc.lt, "reqId": lc.reqID})
	if err != nil {
		return fmt.Errorf("发送短信验证码失败: %w", err)
	}
	var resp struct {
		Result int    `json:"result"`
		Msg    string `json:"msg"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("发送短信验证码失败: 解析响应失败: %w", err)
	}
	if resp.Result == 0 {
		return nil
	}
	switch resp.Result {
	case 20104, 51129:
		return fmt.Errorf("24小时内发送验证码次数过多，请稍后再试")
	case 20107:
		return fmt.Errorf("手机号无效")
	case -10320:
		return fmt.Errorf("该账号不支持短信验证")
	}
	if resp.Msg != "" {
		return fmt.Errorf("发送短信验证码失败: %s", resp.Msg)
	}
	return fmt.Errorf("发送短信验证码失败: result=%d", resp.Result)
}

// submitForSecondAuth 提交短信验证码完成二次校验。
// 错误码：51175/51176=验证码失效（需重新发码），51177=验证码错误，-20099=会话过期。
func (lc *loginContext) submitForSecondAuth(ctx context.Context, mobile string, romaSecondAuth bool, smsCode string) (string, error) {
	// romaSecondAuth=true 时 userName 传明文账号，否则与登录相同的 RSA 加密
	userName := lc.rsaUsername
	if romaSecondAuth {
		userName = lc.c.account
	}
	// epd 加密的是验证码原文，不是密码
	epdEncrypted, err := rsaEncrypt(lc.pubKeyPEM, smsCode)
	if err != nil {
		return "", err
	}
	epd := lc.pre + epdEncrypted

	body, err := lc.c.doPlain(ctx, http.MethodPost, authURL+"/api/logbox/oauth2/submitForSecondAuth.do",
		url.Values{
			"mobile":      {mobile},
			"appKey":      {appID},
			"userName":    {userName},
			"epd":         {epd},
			"accountType": {accountType},
			"returnUrl":   {url.QueryEscape(returnURL)},
			"isOauth2":    {"false"},
			"cb_SaveName": {"1"},
			"state":       {""},
			"paramId":     {lc.paramID},
		}, map[string]string{
			"lt":               lc.lt,
			"reqId":            lc.reqID,
			"Referer":          "https://open.e.189.cn/api/logbox/oauth2/unifyAccountLogin.do",
			"Cookie":           "LT=" + lc.lt,
			"X-Requested-With": "XMLHttpRequest",
		})
	if err != nil {
		return "", fmt.Errorf("提交短信验证码失败: %w", err)
	}
	var resp struct {
		Result int    `json:"result"`
		Msg    string `json:"msg"`
		ToURL  string `json:"toUrl"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("提交短信验证码失败: 解析响应失败: %w", err)
	}
	if resp.Result == 0 && resp.ToURL != "" {
		return resp.ToURL, nil
	}
	switch resp.Result {
	case 51175, 51176:
		return "", fmt.Errorf("验证码已失效，请重新发起登录获取新验证码")
	case 51177:
		return "", fmt.Errorf("验证码错误，请重新输入")
	case -20099:
		return "", fmt.Errorf("登录会话已过期，请重新发起登录")
	}
	if resp.Msg != "" {
		return "", fmt.Errorf("提交短信验证码失败: %s", resp.Msg)
	}
	if resp.ToURL == "" {
		return "", fmt.Errorf("提交短信验证码失败: 响应缺少 toUrl")
	}
	return "", fmt.Errorf("提交短信验证码失败: result=%d", resp.Result)
}
