package cloud189

import "testing"

func TestBuildTaskInfos(t *testing.T) {
	cases := []struct {
		name  string
		isDir bool
		ids   []string
		names map[string]string
		want  string
	}{
		{"目录映射 isFolder=1", true, []string{"a", "b"}, nil,
			`[{"fileId":"a","fileName":"","isFolder":1},{"fileId":"b","fileName":"","isFolder":1}]`},
		{"文件 isFolder=0 且带名字", false, []string{"x"}, map[string]string{"x": "x.txt"},
			`[{"fileId":"x","fileName":"x.txt","isFolder":0}]`},
		{"名字缺失回退为空串", false, []string{"a", "b"}, map[string]string{"b": "B.txt"},
			`[{"fileId":"a","fileName":"","isFolder":0},{"fileId":"b","fileName":"B.txt","isFolder":0}]`},
		{"空 id 列表", false, nil, nil, `[]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildTaskInfos(tc.isDir, tc.ids, tc.names)
			if err != nil {
				t.Fatalf("buildTaskInfos() error: %v", err)
			}
			if got != tc.want {
				t.Errorf("buildTaskInfos() = %s, want %s", got, tc.want)
			}
		})
	}
}
