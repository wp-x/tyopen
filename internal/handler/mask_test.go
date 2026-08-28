package handler

import "testing"

func TestContainsMask(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "空字符串", input: "", want: false},
		{name: "纯掩码", input: "****", want: true},
		{name: "账号掩码（前3后2）", input: "138****34", want: true},
		{name: "token掩码（前5后5）", input: "abcde****fghij", want: true},
		{name: "真实手机号", input: "13800001111", want: false},
		{name: "短字符串不越界", input: "abcde", want: false},
		{name: "6位短串不越界", input: "abcdef", want: false},
		{name: "7位短串不越界", input: "abcdefg", want: false},
		{name: "普通密码", input: "mySecretPwd!", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsMask(tc.input); got != tc.want {
				t.Fatalf("containsMask(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
