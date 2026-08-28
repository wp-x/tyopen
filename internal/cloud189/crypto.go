package cloud189

import (
	"crypto/aes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// clientSuffix 每个 API 请求附加的公共 query 参数
func clientSuffix() map[string]string {
	return map[string]string{
		"clientType": pcClient,
		"version":    version,
		"channelId":  channelID,
		"rand":       fmt.Sprintf("%d_%d", secureRandomInt(1e5), secureRandomInt(1e10)),
	}
}

var urlPathRegexp = regexp.MustCompile(`://[^/]+((/[^/\s?#]+)*)`)

func secureRandomInt(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

// signatureOfHmac 所有业务 API 的 Signature 头（HMAC-SHA1，大写 HEX）
// param 为 AES 加密后的 params query 值（无则传 ""）
func signatureOfHmac(sessionSecret, sessionKey, operate, fullURL, dateOfGmt, param string) string {
	urlpath := ""
	if m := urlPathRegexp.FindStringSubmatch(fullURL); m != nil {
		urlpath = m[1]
	}
	data := fmt.Sprintf("SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", sessionKey, operate, urlpath, dateOfGmt)
	if param != "" {
		data += fmt.Sprintf("&params=%s", param)
	}
	mac := hmac.New(sha1.New, []byte(sessionSecret))
	mac.Write([]byte(data))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

// encryptParams AES-128-ECB + PKCS7 加密 params 原文，key 取 sessionSecret[:16]，
// 输出大写 HEX 作为 params query 参数。params 原文：key 按字典序排序的 k1=v1&k2=v2。
func encryptParams(sessionSecret string, params map[string]string) (string, error) {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+params[k])
	}
	plain := []byte(strings.Join(pairs, "&"))

	key := []byte(sessionSecret)
	if len(key) > aes.BlockSize {
		key = key[:aes.BlockSize]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// PKCS7 填充
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	// ECB 逐块加密
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return strings.ToUpper(hex.EncodeToString(out)), nil
}

// rsaEncrypt 登录用用户名/密码 RSA 加密（PKCS#1 v1.5，大写 HEX）
func rsaEncrypt(publicKeyPEM, origData string) (string, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
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
	data, err := rsa.EncryptPKCS1v15(cryptorand.Reader, pub, []byte(origData))
	if err != nil {
		return "", fmt.Errorf("RSA 加密失败: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(data)), nil
}

// dateOfGMT GMT HTTP 时间格式（Mon, 02 Jan 2006 15:04:05 GMT）
func dateOfGMT() string {
	return time.Now().UTC().Format(http.TimeFormat)
}

// newUUID 生成随机 UUID v4（避免引入第三方依赖）
func newUUID() string {
	var b [16]byte
	_, _ = cryptorand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
