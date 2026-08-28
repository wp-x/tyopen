package cloud189

import (
	"context"
	"crypto/aes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// errCookieInvalid 表示网页版 Cookie 失效（errorCode=InvalidSessionKey）。
// Cookie 模式无自动续期，直接返回明确错误。
var errCookieInvalid = errors.New("Cookie 已失效，请重新获取")

// webBackend 网页版 API 模式（cloud.189.cn，Cookie 会话，小写 HEX）
type webBackend struct {
	c          *Client
	httpClient *http.Client

	mu         sync.Mutex // 保护以下缓存字段
	sessionKey string
	rsaPubKey  string
	rsaPkID    string
	rsaExpire  int64 // 毫秒时间戳
}

func newWebBackend(c *Client) *webBackend {
	return &webBackend{c: c, httpClient: &http.Client{}}
}

// init 验证 Cookie 有效性并缓存上传所需 sessionKey
func (b *webBackend) init(ctx context.Context) error {
	// 用 cookie 列根目录验证有效性
	if _, err := b.listFiles(defaultRootFolderID, 1, 1); err != nil {
		return fmt.Errorf("Cookie 验证失败: %w", err)
	}
	// 缓存上传所需 sessionKey
	if err := b.refreshSessionKey(ctx); err != nil {
		return err
	}
	return nil
}

// request 网页版统一请求模板：Cookie + noCache query，无签名头
func (b *webBackend) request(ctx context.Context, method, fullURL string, query map[string]string, form url.Values) ([]byte, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("noCache", webNoCache())
	for k, v := range query {
		q.Set(k, v)
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
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	req.Header.Set("Referer", "https://cloud.189.cn/")
	req.Header.Set("Cookie", b.c.getCookie())
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// 先检查业务错误：服务端在 Cookie 失效时会返回 HTTP 400 + errorCode JSON，
	// 需要映射成明确的"Cookie 已失效"而不是裸 HTTP 错误
	if err := checkWebBusinessError(body); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

// checkWebBusinessError 检查网页版响应中的 errorCode 与 res_code 业务错误
func checkWebBusinessError(body []byte) error {
	var head struct {
		ErrorCode  string          `json:"errorCode"`
		ErrorMsg   string          `json:"errorMsg"`
		ResCode    json.RawMessage `json:"res_code"`
		ResMessage string          `json:"res_message"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return nil // 非 JSON 响应，不判定业务错误
	}
	if head.ErrorCode == "InvalidSessionKey" {
		return errCookieInvalid
	}
	if head.ErrorCode != "" {
		return fmt.Errorf("errorCode: %s, errorMsg: %s", head.ErrorCode, head.ErrorMsg)
	}
	if code := rawJSONString(head.ResCode); code != "" && code != "0" {
		return fmt.Errorf("res_code: %s, res_message: %s", code, head.ResMessage)
	}
	return nil
}

// webNoCache noCache=0.xxx 缓存破坏参数。仅用于破坏 HTTP 缓存，
// 不参与任何密钥/签名材料生成，故沿用 math/rand；
// 涉及密钥的随机性（randomPattern）统一走 crypto/rand。
func webNoCache() string {
	return fmt.Sprintf("0.%017d", rand.Int63n(1e17))
}

// refreshSessionKey 从 getUserBriefInfo 获取并缓存上传用 sessionKey
func (b *webBackend) refreshSessionKey(ctx context.Context) error {
	body, err := b.request(ctx, http.MethodGet, webURL+"/v2/getUserBriefInfo.action", nil, nil)
	if err != nil {
		return fmt.Errorf("获取 sessionKey 失败: %w", err)
	}
	var resp struct {
		SessionKey string `json:"sessionKey"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.SessionKey == "" {
		return fmt.Errorf("获取 sessionKey 失败: 响应缺少 sessionKey")
	}
	b.mu.Lock()
	b.sessionKey = resp.SessionKey
	b.mu.Unlock()
	return nil
}

func (b *webBackend) getSessionKey() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessionKey
}

// getRsaKey 获取上传签名用的 RSA 公钥（带过期缓存）
func (b *webBackend) getRsaKey(ctx context.Context) (pubKey, pkID string, err error) {
	now := time.Now().UnixMilli()
	b.mu.Lock()
	if b.rsaPubKey != "" && b.rsaExpire > now {
		pubKey, pkID = b.rsaPubKey, b.rsaPkID
		b.mu.Unlock()
		return pubKey, pkID, nil
	}
	b.mu.Unlock()

	body, err := b.request(ctx, http.MethodGet, webURL+"/api/security/generateRsaKey.action", nil, nil)
	if err != nil {
		return "", "", fmt.Errorf("获取RSA公钥失败: %w", err)
	}
	var resp struct {
		PubKey string `json:"pubKey"`
		PkID   string `json:"pkId"`
		Expire int64  `json:"expire"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.PubKey == "" {
		return "", "", fmt.Errorf("获取RSA公钥失败: 响应缺少 pubKey")
	}
	b.mu.Lock()
	b.rsaPubKey, b.rsaPkID, b.rsaExpire = resp.PubKey, resp.PkID, resp.Expire
	b.mu.Unlock()
	return resp.PubKey, resp.PkID, nil
}

// ============ 网页版加密工具（输出全部为小写 HEX / base64，与 PC 模式大写不同） ============

// aesECBEncrypt AES-128-ECB + PKCS7 加密，输出原始字节
func aesECBEncrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return out, nil
}

// hmacSha1Lower HMAC-SHA1，小写 HEX（网页版）
func hmacSha1Lower(data, secret string) string {
	h := hmac.New(sha1.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// rsaEncryptBase64 网页版 RSA 加密（PKCS#1 v1.5，base64 输出）
func rsaEncryptBase64(pubKeyBase64 string, origData []byte) (string, error) {
	publicKey := []byte("-----BEGIN PUBLIC KEY-----\n" + pubKeyBase64 + "\n-----END PUBLIC KEY-----")
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "", fmt.Errorf("解析 RSA 公钥 PEM 失败")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("解析 RSA 公钥失败: %w", err)
	}
	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("公钥类型不是 RSA")
	}
	data, err := rsa.EncryptPKCS1v15(cryptorand.Reader, pub, origData)
	if err != nil {
		return "", fmt.Errorf("RSA 加密失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// randHexNibble 从 crypto/rand 读取一个随机 nibble（0-15）。
// randomPattern 用于生成上传 AES key 与 requestID，必须使用密码学
// 安全随机源，不能用 math/rand。
func randHexNibble() (byte, error) {
	var b [1]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return 0, err
	}
	return b[0] & 0x0f, nil
}

// randomPattern 按 OpenList Random 实现：x→随机十六进制位，y→(3&t)|8。
// 随机性来自 crypto/rand（见 randHexNibble）。
func randomPattern(pattern string) string {
	var sb strings.Builder
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case 'x', 'y':
			t, err := randHexNibble()
			if err != nil {
				// crypto/rand 不可用（正常不会发生）：回退为 0，仅保证输出格式稳定
				t = 0
			}
			if ch == 'x' {
				sb.WriteString(strconv.FormatInt(int64(t), 16))
			} else {
				sb.WriteString(strconv.FormatInt(int64(3&t|8), 16))
			}
		default:
			sb.WriteByte(ch)
		}
	}
	return sb.String()
}

// randKeyLength 返回 16~31 的随机长度（crypto/rand），用于 AES key 长度随机化。
func randKeyLength() int {
	t, err := randHexNibble()
	if err != nil {
		return 16
	}
	return 16 + int(t%16)
}

// encodeWebForm 网页版上传 params 原文：k=v 用 & 连接（key 排序保证确定性，
// 值不转义——fileName 等需要转义的值由调用方预先 QueryEscape）
func encodeWebForm(form map[string]string) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+form[k])
	}
	return strings.Join(pairs, "&")
}
