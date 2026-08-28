package cloud189

import (
	"strings"
	"testing"
	"time"
)

func TestParse189Time(t *testing.T) {
	base := time.Date(2023, 1, 2, 15, 4, 5, 0, time.Local)
	cases := []struct {
		name   string
		values []string
		want   time.Time // 与解析结果用 Equal 比较（瞬时相等）
	}{
		{"标准格式", []string{"2023-01-02 15:04:05"}, base},
		{"斜杠格式", []string{"2023/01/02 15:04:05"}, base},
		{"美式带逗号", []string{"Jan 2, 2023, 3:04:05 PM"}, base},
		{"美式无逗号", []string{"Jan 2, 2023 3:04:05 PM"}, base},
		{"紧凑格式", []string{"20230102150405"}, base},
		{"RFC3339 带时区", []string{"2023-01-02T15:04:05+08:00"},
			time.Date(2023, 1, 2, 15, 4, 5, 0, time.FixedZone("", 8*3600))},
		{"U+202F 窄不换行空格", []string{"2023-01-02\u202f15:04:05"}, base},
		{"U+00A0 不换行空格", []string{"2023-01-02\u00a015:04:05"}, base},
		{"首尾空白被裁剪", []string{"  2023-01-02 15:04:05  "}, base},
		{"空值跳过取第二个", []string{"", "2023-01-02 15:04:05"}, base},
		{"首个非法取第二个", []string{"garbage", "2023-01-02 15:04:05"}, base},
		{"全部非法 → 零值", []string{"not a date"}, time.Time{}},
		{"空值列表 → 零值", []string{""}, time.Time{}},
		{"无参数 → 零值", nil, time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parse189Time(tc.values...)
			if tc.want.IsZero() {
				if !got.IsZero() {
					t.Errorf("parse189Time(%v) = %v, want zero time", tc.values, got)
				}
				return
			}
			if !got.Equal(tc.want) {
				t.Errorf("parse189Time(%v) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

func TestDownloadErrorMessage(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"JSON errorCode/errorMsg", 404, `{"errorCode":"FileNotFound","errorMsg":"文件不存在"}`,
			"文件不存在 (FileNotFound)"},
		{"JSON res_code/res_message", 500, `{"res_code":1001,"res_message":"参数错误"}`,
			"参数错误"},
		{"XML Code/Message", 403,
			`<Error><Code>FileNotFound</Code><Message>The specified key does not exist.</Message></Error>`,
			"The specified key does not exist. (FileNotFound)"},
		{"XML 只有 Code", 403, `<Error><Code>FileNotFound</Code></Error>`, "FileNotFound"},
		{"非结构兜底 HTTP", 404, `boom`, "HTTP 404: boom"},
		{"超长正文截断 200", 404, strings.Repeat("a", 250), "HTTP 404: " + strings.Repeat("a", 200)},
		{"空正文", 500, ``, "HTTP 500: "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := downloadErrorMessage(tc.status, []byte(tc.body)); got != tc.want {
				t.Errorf("downloadErrorMessage(%d, %q) = %q, want %q", tc.status, tc.body, got, tc.want)
			}
		})
	}
}

func TestXMLTagValue(t *testing.T) {
	cases := []struct {
		name string
		s    string
		tag  string
		want string
	}{
		{"简单标签", "<Code>abc</Code>", "Code", "abc"},
		{"嵌套在根内", "<Error><Code>x</Code></Error>", "Code", "x"},
		{"标签不存在", "<Error></Error>", "Message", ""},
		{"闭合标签缺失", "<Code>abc", "Code", ""},
		{"开标签缺失", "</Code>", "Code", ""},
		{"空内容", "<Code></Code>", "Code", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := xmlTagValue(tc.s, tc.tag); got != tc.want {
				t.Errorf("xmlTagValue(%q, %q) = %q, want %q", tc.s, tc.tag, got, tc.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"未超长", "short", 10, "short"},
		{"超长截断", "abcdef", 3, "abc"},
		{"空串", "", 5, ""},
		{"恰好等长", "abc", 3, "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.s, tc.n); got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
			}
		})
	}
}
