package handler

import (
	"strings"
	"testing"
)

func TestGenerateShareCodeHas64BitsOfEntropySpace(t *testing.T) {
	code, err := generateShareCode()
	if err != nil {
		t.Fatalf("生成分享码失败: %v", err)
	}
	if len(code) != 16 {
		t.Fatalf("分享码长度错误：got=%d want=16", len(code))
	}
	if strings.Trim(code, "0123456789abcdef") != "" {
		t.Fatalf("分享码不是小写 HEX: %q", code)
	}
}

func TestValidateShareCode(t *testing.T) {
	for _, code := range []string{"abc", "A-B_c9", strings.Repeat("a", 64)} {
		if err := validateShareCode(code); err != nil {
			t.Fatalf("合法分享码 %q 被拒绝: %v", code, err)
		}
	}
	for _, code := range []string{"has space", "a/b", "中文", strings.Repeat("a", 65)} {
		if err := validateShareCode(code); err == nil {
			t.Fatalf("非法分享码 %q 应被拒绝", code)
		}
	}
}

func TestParseShareExpireAtRejectsInvalidValue(t *testing.T) {
	if _, err := parseShareExpireAt("not-a-time"); err == nil {
		t.Fatal("无效过期时间应返回错误")
	}
	if got, err := parseShareExpireAt(""); err != nil || got != nil {
		t.Fatalf("空过期时间应表示永不过期：got=%v err=%v", got, err)
	}
}
