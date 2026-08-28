package cloud189

import (
	"os"
)

// TempFileUploader 供 WebDAV 等调用方把上传数据落盘，避免整文件驻留内存。
func TempFileUploader(prefix string) (*os.File, error) {
	return os.CreateTemp("", prefix)
}
