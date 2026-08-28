package cloud189

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"testing"
)

func TestComputeMD5s(t *testing.T) {
	const content = "hello world"
	const knownFileMD5 = "5EB63BBBE01EEED093CB22BB8F5ACDC3"

	t.Run("单片：sliceMd5 等于 fileMd5", func(t *testing.T) {
		res, err := computeMD5s(bytes.NewReader([]byte(content)), int64(len(content)), int64(len(content)))
		if err != nil {
			t.Fatalf("computeMD5s() error: %v", err)
		}
		if res.fileMD5 != knownFileMD5 {
			t.Errorf("fileMD5 = %s, want %s", res.fileMD5, knownFileMD5)
		}
		if res.sliceMD5 != knownFileMD5 {
			t.Errorf("sliceMD5 = %s, want %s", res.sliceMD5, knownFileMD5)
		}
		if len(res.slices) != 1 {
			t.Fatalf("slices = %d, want 1", len(res.slices))
		}
		if res.slices[0].hexUpper != knownFileMD5 {
			t.Errorf("slice hex = %s, want %s", res.slices[0].hexUpper, knownFileMD5)
		}
		// base64 字段应为原始 16 字节摘要
		raw, err := base64.StdEncoding.DecodeString(res.slices[0].base64)
		if err != nil {
			t.Fatalf("slice base64 decode: %v", err)
		}
		sum := md5.Sum([]byte(content))
		if !bytes.Equal(raw, sum[:]) {
			t.Errorf("slice base64 decodes to %x, want %x", raw, sum[:])
		}
	})

	t.Run("多片：sliceMd5 为各片 HEX 用换行拼接后再 MD5", func(t *testing.T) {
		const sliceSize = 5
		res, err := computeMD5s(bytes.NewReader([]byte(content)), int64(len(content)), sliceSize)
		if err != nil {
			t.Fatalf("computeMD5s() error: %v", err)
		}
		if res.fileMD5 != knownFileMD5 {
			t.Errorf("fileMD5 = %s, want %s", res.fileMD5, knownFileMD5)
		}
		wantSlices := []string{
			"5D41402ABC4B2A76B9719D911017C592", // MD5("hello")
			"B81A02D933DAA824C9B06DE373B77D70", // MD5(" worl")
			"8277E0910D750195B448797616E091AD", // MD5("d")
		}
		if len(res.slices) != len(wantSlices) {
			t.Fatalf("slices = %d, want %d", len(res.slices), len(wantSlices))
		}
		for i, w := range wantSlices {
			if res.slices[i].hexUpper != w {
				t.Errorf("slice[%d] hex = %s, want %s", i, res.slices[i].hexUpper, w)
			}
		}
		// sliceMd5 = MD5("hello\n worl\nd" 三个 HEX 用 \n 拼接)
		if want := "F5260B990E6DFA5B0E3B1D522D258D11"; res.sliceMD5 != want {
			t.Errorf("sliceMD5 = %s, want %s", res.sliceMD5, want)
		}
	})

	t.Run("多片整除：正好两片", func(t *testing.T) {
		const content2 = "0123456789"
		res, err := computeMD5s(bytes.NewReader([]byte(content2)), int64(len(content2)), 5)
		if err != nil {
			t.Fatalf("computeMD5s() error: %v", err)
		}
		want := []string{"4100C4D44DA9177247E44A5FC1546778", "099EBEA48EA9666A7DA2177267983138"}
		if len(res.slices) != 2 {
			t.Fatalf("slices = %d, want 2", len(res.slices))
		}
		for i, w := range want {
			if res.slices[i].hexUpper != w {
				t.Errorf("slice[%d] hex = %s, want %s", i, res.slices[i].hexUpper, w)
			}
		}
		if want := "FC6E562CD41A11BA2A6D31144227160B"; res.sliceMD5 != want {
			t.Errorf("sliceMD5 = %s, want %s", res.sliceMD5, want)
		}
	})

	t.Run("空文件：一个分片", func(t *testing.T) {
		const emptyMD5 = "D41D8CD98F00B204E9800998ECF8427E"
		res, err := computeMD5s(bytes.NewReader(nil), 0, 1024)
		if err != nil {
			t.Fatalf("computeMD5s() error: %v", err)
		}
		if res.fileMD5 != emptyMD5 {
			t.Errorf("fileMD5 = %s, want %s", res.fileMD5, emptyMD5)
		}
		if len(res.slices) != 1 {
			t.Fatalf("slices = %d, want 1", len(res.slices))
		}
		if res.sliceMD5 != emptyMD5 {
			t.Errorf("sliceMD5 = %s, want %s", res.sliceMD5, emptyMD5)
		}
	})

	t.Run("读取器错误透传", func(t *testing.T) {
		if _, err := computeMD5s(errReader{}, 10, 5); err == nil {
			t.Error("computeMD5s with failing reader should error")
		}
	})
}

// errReader 读取即失败，用于验证 computeMD5s 的错误透传。
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
func (errReader) Seek(int64, int) (int64, error) {
	return 0, nil
}

func TestSliceSizeFor(t *testing.T) {
	const s10 = int64(10 * 1024 * 1024) // 10MiB
	cases := []struct {
		name string
		size int64
		want int64
	}{
		{"空文件", 0, s10},
		{"恰好 999 片", s10 * 999, s10},
		{"999 片 +1 升到 20MiB", s10*999 + 1, s10 * 2},
		{"恰好 20MiB 档上限(1998 片)", s10 * 2 * 999, s10 * 2},
		{"1998 片 +1 进入大文件档", s10*2*999 + 1, s10 * 5}, // mult=ceil(3997/1999)=1 → 最小 5
		{"mult 正好 5", s10 * 1999 * 5, s10 * 5},
		{"mult 6", s10*1999*5 + 1, s10 * 6},
		{"超大文件 mult=100", s10 * 1999 * 100, s10 * 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sliceSizeFor(tc.size); got != tc.want {
				t.Errorf("sliceSizeFor(%d) = %d, want %d", tc.size, got, tc.want)
			}
		})
	}
}
