package cloud189

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// request 统一业务请求模板：clientSuffix query + 可选 AES params + 四签名头。
// 遇到 session 失效（响应含 "userSessionBO is null" 或 "InvalidSessionKey"）自动
// 刷新 session 重试；token 失效（res_code=UserInvalidOpenToken）刷新 token 后重试。
// 刷新重试上限 3 次。
func (c *Client) request(ctx context.Context, method, fullURL string, query map[string]string, aesParams map[string]string, form url.Values) ([]byte, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.ensureSession(ctx); err != nil {
			return nil, err
		}
		body, err := c.doSignedRequest(ctx, method, fullURL, query, aesParams, form)
		if err == nil {
			return body, nil
		}
		if isSessionOrTokenInvalid(err) {
			lastErr = err
			if refreshErr := c.refreshSession(ctx); refreshErr != nil {
				return nil, fmt.Errorf("刷新会话失败: %w（原始错误: %v）", refreshErr, err)
			}
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("会话失效，刷新后仍失败: %w", lastErr)
}

func isSessionOrTokenInvalid(err error) bool {
	return err == errSessionInvalid || err == errInvalidOpenToken
}

// doSignedRequest 执行一次带签名头的请求并检查业务错误
func (c *Client) doSignedRequest(ctx context.Context, method, fullURL string, query map[string]string, aesParams map[string]string, form url.Values) ([]byte, error) {
	sessionKey, sessionSecret := c.getSession()
	if sessionKey == "" || sessionSecret == "" {
		return nil, errSessionInvalid
	}

	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k, v := range clientSuffix() {
		q.Set(k, v)
	}
	for k, v := range query {
		q.Set(k, v)
	}

	// AES 加密 params（如有），加密值同时参与签名
	param := ""
	if aesParams != nil {
		param, err = encryptParams(sessionSecret, aesParams)
		if err != nil {
			return nil, fmt.Errorf("加密请求参数失败: %w", err)
		}
		q.Set("params", param)
	}
	u.RawQuery = q.Encode()

	var bodyReader io.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	date := dateOfGMT()
	req.Header.Set("Date", date)
	req.Header.Set("SessionKey", sessionKey)
	req.Header.Set("X-Request-ID", newUUID())
	req.Header.Set("Signature", signatureOfHmac(sessionSecret, sessionKey, strings.ToUpper(method), fullURL, date, param))
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	req.Header.Set("Referer", webURL)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	if err := checkBusinessError(body); err != nil {
		return nil, err
	}
	return body, nil
}

// checkBusinessError 检查响应中的 session/token 失效标记与 res_code 业务错误
func checkBusinessError(body []byte) error {
	s := string(body)
	if strings.Contains(s, "userSessionBO is null") || strings.Contains(s, "InvalidSessionKey") {
		return errSessionInvalid
	}
	if strings.Contains(s, "UserInvalidOpenToken") {
		return errInvalidOpenToken
	}

	var head struct {
		ResCode    json.RawMessage `json:"res_code"`
		ResMessage string          `json:"res_message"`
	}
	if err := json.Unmarshal(body, &head); err != nil || len(head.ResCode) == 0 {
		return nil // 非统一 JSON 结构（如纯文本响应），不判定业务错误
	}
	code := rawJSONString(head.ResCode)
	if code == "" || code == "0" {
		return nil
	}
	return fmt.Errorf("res_code: %s, res_message: %s", code, head.ResMessage)
}

// rawJSONString 把 JSON 值（字符串或数字）转为字符串形式
func rawJSONString(v json.RawMessage) string {
	s := strings.TrimSpace(string(v))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var str string
		if err := json.Unmarshal(v, &str); err == nil {
			return str
		}
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
