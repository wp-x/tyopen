package cloud189

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckBusinessError(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		want  error  // 非 nil 时要求 err == want
		match string // want 为 nil 但非空时，要求错误信息包含该子串
	}{
		{"明文 userSessionBO is null", `userSessionBO is null`, errSessionInvalid, ""},
		{"JSON 内含 userSessionBO is null", `{"res_code":0,"res_message":"userSessionBO is null"}`, errSessionInvalid, ""},
		{"明文 InvalidSessionKey", `InvalidSessionKey`, errSessionInvalid, ""},
		{"JSON errorCode InvalidSessionKey", `{"errorCode":"InvalidSessionKey"}`, errSessionInvalid, ""},
		{"明文 UserInvalidOpenToken", `UserInvalidOpenToken`, errInvalidOpenToken, ""},
		{"res_code 非零数字", `{"res_code":1001,"res_message":"参数错误"}`, nil, "res_code: 1001"},
		{"res_code 非零字符串", `{"res_code":"1001","res_message":"bad"}`, nil, "res_code: 1001"},
		{"res_code 非数字串", `{"res_code":"abc"}`, nil, "res_code: abc"},
		{"res_code 为 0", `{"res_code":0}`, nil, ""},
		{"res_code 字符串 0", `{"res_code":"0"}`, nil, ""},
		{"正常业务 JSON", `{"data":{}}`, nil, ""},
		{"非 JSON", `not json at all`, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBusinessError([]byte(tc.body))
			if tc.want != nil {
				if err != tc.want {
					t.Errorf("checkBusinessError() = %v, want %v", err, tc.want)
				}
				return
			}
			if tc.match != "" {
				if err == nil || !strings.Contains(err.Error(), tc.match) {
					t.Errorf("checkBusinessError() = %v, want error containing %q", err, tc.match)
				}
				return
			}
			if err != nil {
				t.Errorf("checkBusinessError() = %v, want nil", err)
			}
		})
	}
}

func TestRawJSONString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"带引号字符串", `"123"`, "123"},
		{"数字", `123`, "123"},
		{"字符串", `"hello"`, "hello"},
		{"空字符串", `""`, ""},
		{"含转义引号", `"a\"b"`, `a"b`},
		{"布尔", `true`, "true"},
		{"null", `null`, "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawJSONString(json.RawMessage(tc.in)); got != tc.want {
				t.Errorf("rawJSONString(%s) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
