package cloud189

import (
	"crypto/aes"
	"regexp"
	"strings"
	"testing"
)

func TestRandomPattern(t *testing.T) {
	patterns := []string{
		"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx", // requestID 格式
		"xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx",     // 上传 AES key 格式
		"x",
		"y",
		"4-xy-",
	}
	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			for i := 0; i < 300; i++ {
				got := randomPattern(p)
				if len(got) != len(p) {
					t.Fatalf("randomPattern(%q) len = %d, want %d", p, len(got), len(p))
				}
				for j := 0; j < len(p); j++ {
					switch p[j] {
					case 'x':
						if !strings.ContainsRune("0123456789abcdef", rune(got[j])) {
							t.Fatalf("position %d = %q, want hex digit 0-9a-f", j, got[j])
						}
					case 'y':
						if !strings.ContainsRune("89ab", rune(got[j])) {
							t.Fatalf("position %d = %q, want one of 89ab", j, got[j])
						}
					default:
						if got[j] != p[j] {
							t.Fatalf("literal position %d = %q, want %q", j, got[j], p[j])
						}
					}
				}
			}
		})
	}

	// 随机性冒烟：多次生成中每个 x/y 位置都应出现多种取值
	t.Run("随机性", func(t *testing.T) {
		const n = 500
		pattern := "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
		seen := make(map[int]map[byte]bool)
		for i := 0; i < n; i++ {
			got := randomPattern(pattern)
			for j := 0; j < len(got); j++ {
				if pattern[j] != 'x' && pattern[j] != 'y' {
					continue
				}
				if seen[j] == nil {
					seen[j] = make(map[byte]bool)
				}
				seen[j][got[j]] = true
			}
		}
		for j, set := range seen {
			if len(set) < 2 {
				t.Errorf("position %d only produced %d distinct values in %d runs", j, len(set), n)
			}
		}
	})
}

func TestEncodeWebForm(t *testing.T) {
	form := map[string]string{
		"z": "1",
		"a": "hello world",
		"m": "x=y&",
		"b": "2",
	}
	// key 按字典序，值不转义
	if got := encodeWebForm(form); got != "a=hello world&b=2&m=x=y&&z=1" {
		t.Errorf("encodeWebForm() = %q, want %q", got, "a=hello world&b=2&m=x=y&&z=1")
	}
	if got := encodeWebForm(map[string]string{}); got != "" {
		t.Errorf("encodeWebForm(empty) = %q, want empty", got)
	}
}

func TestAESECBEncrypt(t *testing.T) {
	key := []byte("0123456789abcdef")
	cases := []struct {
		name  string
		plain string
	}{
		{"短于一个块", "hello"},
		{"恰好一个块", "0123456789abcdef"},             // 16 字节 → 填充一整块 0x10
		{"跨多个块", "0123456789abcdef0123456789abc"}, // 31 字节
		{"空串", ""}, // 空 → 一整块 0x10
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := aesECBEncrypt([]byte(tc.plain), key)
			if err != nil {
				t.Fatalf("aesECBEncrypt() error: %v", err)
			}
			if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
				t.Fatalf("ciphertext len %d, not a positive multiple of 16", len(ct))
			}
			// 往返：自写解密 + PKCS7 校验
			padded, err := testAESECBDecrypt(ct, key)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			plain, err := testPKCS7Unpad(padded)
			if err != nil {
				t.Fatalf("unpad: %v", err)
			}
			if string(plain) != tc.plain {
				t.Errorf("roundtrip = %q, want %q", plain, tc.plain)
			}
		})
	}
	// 非法 key 长度 → 报错
	if _, err := aesECBEncrypt([]byte("hello"), []byte("short")); err == nil {
		t.Error("aesECBEncrypt with invalid key length should error")
	}
}

func TestWebNoCache(t *testing.T) {
	re := regexp.MustCompile(`^0\.[0-9]{17}$`)
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		got := webNoCache()
		if !re.MatchString(got) {
			t.Fatalf("webNoCache() = %q, want format 0. + 17 digits", got)
		}
		if len(got) != 19 {
			t.Fatalf("webNoCache() = %q, len = %d, want 19", got, len(got))
		}
		seen[got] = true
	}
	if len(seen) < 2 {
		t.Error("webNoCache() not varying across calls")
	}
}
