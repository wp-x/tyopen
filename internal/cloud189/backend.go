package cloud189

import (
	"context"
	"io"
	"tyopen/internal/model"
)

// panBackend 云盘后端模式抽象：pcBackend 走 PC 协议（sessionKey 签名），
// webBackend 走网页版 API（Cookie 会话）。两种模式对外 Client 契约一致。
type panBackend interface {
	// init 建立会话/验证凭据有效性
	init(ctx context.Context) error
	// listFiles 列目录（dirID ""/"0" 由实现映射为根目录）
	listFiles(ctx context.Context, dirID string, page, pageSize int) ([]*model.FileInfo, error)
	// getDownloadURL 获取下载直链
	getDownloadURL(ctx context.Context, fileID string) (string, error)
	// createDirectory 新建目录
	createDirectory(ctx context.Context, parentID, dirName string) (*model.FileInfo, error)
	// rename 重命名文件/目录
	rename(ctx context.Context, isDir bool, id, newName string) error
	// runBatch 批量任务（MOVE/COPY/DELETE，同类型一批）；
	// names 为 fileId → 真实文件名（MOVE/COPY 必须，DELETE 可空）
	runBatch(ctx context.Context, taskType string, isDir bool, ids []string, names map[string]string, targetDirID string) error
	// getFileName 按 fileId 取文件/目录名（批量任务补全 taskInfos 用）
	getFileName(ctx context.Context, id string) (string, error)
	// upload 上传（seeker 已定位到开头，size 为总字节数）
	upload(ctx context.Context, parentID, fileName string, size int64, seeker io.ReadSeeker, onProgress func(uploaded, total int64)) (*model.FileInfo, error)
}

// pcBackend PC 协议模式（api.cloud.189.cn，sessionKey+HMAC 签名，大写 HEX）
type pcBackend struct {
	c *Client
}

// init 建立会话：优先 refreshToken 换 session，失败回退密码登录
func (b *pcBackend) init(ctx context.Context) error {
	return b.c.refreshSession(ctx)
}
