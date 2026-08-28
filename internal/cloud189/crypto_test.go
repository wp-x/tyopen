package cloud189

import (
	"bytes"
	"crypto/aes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// testAESECBDecrypt 测试内自写的 AES-128-ECB 解密助手，
// 用于 encryptParams / aesECBEncrypt 的往返验证（不引入第三方依赖）。
func testAESECBDecrypt(ct, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext length not a multiple of block size")
	}
	out := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	return out, nil
}

// testPKCS7Unpad 校验并去除 PKCS7 填充。
func testPKCS7Unpad(padded []byte) ([]byte, error) {
	if len(padded) == 0 || len(padded)%aes.BlockSize != 0 {
		return nil, errors.New("invalid padded length")
	}
	pad := int(padded[len(padded)-1])
	if pad < 1 || pad > aes.BlockSize {
		return nil, errors.New("invalid PKCS7 pad value")
	}
	for i := len(padded) - pad; i < len(padded); i++ {
		if padded[i] != byte(pad) {
			return nil, errors.New("invalid PKCS7 padding bytes")
		}
	}
	return padded[:len(padded)-pad], nil
}

func TestSignatureOfHmac(t *testing.T) {
	const (
		sessionSecret = "sec"
		sessionKey    = "key"
		date          = "Mon, 02 Jan 2023 15:04:05 GMT"
		fullURL       = "https://cloud.189.cn/api/open/file/listFiles.action"
	)
	// 已知输入 → 已知输出：40 位大写 HEX（HMAC-SHA1(数据, sec)）
	want := "914DDBAF5A201196A16DCBE4EAFCE73F96593876"
	got := signatureOfHmac(sessionSecret, sessionKey, "GET", fullURL, date, "")
	if got != want {
		t.Errorf("signatureOfHmac() = %s, want %s", got, want)
	}
	if !regexp.MustCompile(`^[0-9A-F]{40}$`).MatchString(got) {
		t.Errorf("signatureOfHmac() = %s, not 40 uppercase hex chars", got)
	}
	// 含 params 时签名必须变化
	if with := signatureOfHmac(sessionSecret, sessionKey, "GET", fullURL, date, "paramValue"); with == got {
		t.Error("signature with params should differ from signature without")
	}
	// 不同 Date 输出不同
	if other := signatureOfHmac(sessionSecret, sessionKey, "GET", fullURL, "Mon, 03 Jan 2023 15:04:05 GMT", ""); other == got {
		t.Error("signature with different Date should differ")
	}
	// 不同 URL 路径输出不同
	if other := signatureOfHmac(sessionSecret, sessionKey, "GET", "https://cloud.189.cn/api/open/listFiles.action", date, ""); other == got {
		t.Error("signature with different path should differ")
	}
}

func TestEncryptParams(t *testing.T) {
	key := []byte("0123456789abcdef")
	params := map[string]string{"b": "2", "a": "1", "c": "3"}
	wantPlain := "a=1&b=2&c=3"

	decryptRoundtrip := func(t *testing.T, out, k string, want string) {
		t.Helper()
		ct, err := hex.DecodeString(out)
		if err != nil {
			t.Fatalf("hex decode: %v", err)
		}
		padded, err := testAESECBDecrypt(ct, []byte(k))
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		plain, err := testPKCS7Unpad(padded)
		if err != nil {
			t.Fatalf("unpad: %v", err)
		}
		if !bytes.Equal(plain, []byte(want)) {
			t.Errorf("roundtrip plaintext = %q, want %q", plain, want)
		}
	}

	out, err := encryptParams(string(key), params)
	if err != nil {
		t.Fatalf("encryptParams() error: %v", err)
	}
	// 大写 HEX，且为 16 字节块（32 hex 字符）的整数倍
	if !regexp.MustCompile(`^[0-9A-F]+$`).MatchString(out) {
		t.Errorf("encryptParams() = %s, not uppercase hex", out)
	}
	if len(out)%32 != 0 {
		t.Errorf("encryptParams() length %d, not multiple of 32 hex chars", len(out))
	}
	// 往返：自写 AES-128-ECB 解密 + PKCS7 校验 + key 字典序原文
	decryptRoundtrip(t, out, string(key), wantPlain)

	// 空 params → 一整块 0x10 填充
	outEmpty, err := encryptParams(string(key), map[string]string{})
	if err != nil {
		t.Fatalf("encryptParams(empty) error: %v", err)
	}
	if len(outEmpty) != 32 {
		t.Errorf("encryptParams(empty) length = %d, want 32", len(outEmpty))
	}
	decryptRoundtrip(t, outEmpty, string(key), "")

	// key > 16 字节：截断为前 16 字节
	longKey := "0123456789abcdef0123456789abcdef" // 32 字节
	outLong, err := encryptParams(longKey, params)
	if err != nil {
		t.Fatalf("encryptParams(longKey) error: %v", err)
	}
	decryptRoundtrip(t, outLong, longKey[:16], wantPlain)
	// 用完整 32 字节 key 解密不应得到原文（证明加密用的是前 16 字节）
	if got, err := testAESECBDecrypt(mustHex(t, outLong), []byte(longKey)); err == nil {
		if unpadded, uerr := testPKCS7Unpad(got); uerr == nil && bytes.Equal(unpadded, []byte(wantPlain)) {
			t.Error("decrypt with full 32-byte key unexpectedly matched plaintext")
		}
	}

	// key 不足 16 字节 → 报错
	if _, err := encryptParams("short", params); err == nil {
		t.Error("encryptParams with key < 16 bytes should error")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func TestRSAEncrypt(t *testing.T) {
	priv, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	orig := "login-password-内容"
	out, err := rsaEncrypt(pubPEM, orig)
	if err != nil {
		t.Fatalf("rsaEncrypt() error: %v", err)
	}
	// 大写 HEX
	if !regexp.MustCompile(`^[0-9A-F]+$`).MatchString(out) {
		t.Errorf("rsaEncrypt() = %s, not uppercase hex", out)
	}
	// 往返：私钥解密得到原文
	pt, err := rsa.DecryptPKCS1v15(cryptorand.Reader, priv, mustHex(t, out))
	if err != nil {
		t.Fatalf("rsa decrypt: %v", err)
	}
	if string(pt) != orig {
		t.Errorf("roundtrip plaintext = %q, want %q", pt, orig)
	}

	// 无效 PEM → 明确错误
	if _, err := rsaEncrypt("not a pem", orig); err == nil {
		t.Error("rsaEncrypt with invalid PEM should error")
	}
}

func TestNewUUID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		u := newUUID()
		if !re.MatchString(u) {
			t.Fatalf("newUUID() = %q, format mismatch", u)
		}
		// 版本位：b[6] 高 nibble = 4（uuid 第 15 个字符）
		if u[14] != '4' {
			t.Fatalf("newUUID() = %q, version char at pos 14 = %q, want '4'", u, u[14])
		}
		// 变体位：b[8] 高 nibble ∈ {8,9,a,b}（uuid 第 20 个字符）
		if !strings.ContainsRune("89ab", rune(u[19])) {
			t.Fatalf("newUUID() = %q, variant char at pos 19 = %q, want one of 89ab", u, u[19])
		}
		seen[u] = true
	}
	if len(seen) != 200 {
		t.Errorf("newUUID() produced %d unique values in 200 calls", len(seen))
	}
}
