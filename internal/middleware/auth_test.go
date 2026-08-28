package middleware

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestTokenVersionRevokesExistingTokens(t *testing.T) {
	oldSecret := JWTSecret
	oldVersion := AdminTokenVersion()
	defer func() {
		JWTSecret = oldSecret
		SetAdminTokenVersion(oldVersion)
	}()

	JWTSecret = "test-secret-with-at-least-32-characters-123456"
	SetAdminTokenVersion(7)
	token, err := GenerateToken("forever")
	if err != nil {
		t.Fatalf("生成 token 失败: %v", err)
	}
	if !ValidateToken(token) {
		t.Fatal("相同 token version 的 token 应有效")
	}

	SetAdminTokenVersion(8)
	if ValidateToken(token) {
		t.Fatal("会话版本递增后旧 token 应失效")
	}
}

func TestLegacyTokenAcceptedOnlyAtVersionZero(t *testing.T) {
	oldSecret := JWTSecret
	oldVersion := AdminTokenVersion()
	defer func() {
		JWTSecret = oldSecret
		SetAdminTokenVersion(oldVersion)
	}()

	JWTSecret = "test-secret-with-at-least-32-characters-123456"
	SetAdminTokenVersion(0)
	legacyToken, err := (&jwtTokenBuilder{}).signWithoutVersion()
	if err != nil {
		t.Fatalf("生成 legacy token 失败: %v", err)
	}
	if !ValidateToken(legacyToken) {
		t.Fatal("版本 0 时旧 token 应保持兼容")
	}
	SetAdminTokenVersion(1)
	if ValidateToken(legacyToken) {
		t.Fatal("版本递增后旧 token 应失效")
	}
}

// jwtTokenBuilder 仅用于构造升级前不含 ver claim 的 legacy token。
type jwtTokenBuilder struct{}

func (b *jwtTokenBuilder) signWithoutVersion() (string, error) {
	claims := jwt.MapClaims{
		"iat": time.Now().Unix(),
		"iss": "tyopen",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(JWTSecret))
}
