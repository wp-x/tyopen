package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tyopen/internal/model"

	"github.com/gin-gonic/gin"
)

const (
	maxTextPreviewBytes int64 = 5 * 1024 * 1024
	maxPDFPreviewBytes  int64 = 100 * 1024 * 1024
	maxPDFPreviewSlots        = 8
)

var (
	errTextPreviewTooLarge = errors.New("文件超过 5 MiB 文本预览上限")
	pdfPreviewSlots        = make(chan struct{}, maxPDFPreviewSlots)
)

// HTTPDoer 是文本代理所需的最小 HTTP 客户端接口，便于替换和测试。
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// GetFileContent 通过服务端读取文件内容，避免浏览器直接请求云盘直链触发 CORS。
func (h *Handler) GetFileContent(c *gin.Context) {
	fid := c.Query("fid")
	if fid == "" {
		writeFileContentError(c, http.StatusBadRequest, "缺少 fid")
		return
	}

	content, err := h.loadFileContent(c.Request.Context(), fid)
	if err != nil {
		writeFileContentLoadError(c, err)
		return
	}

	writeFileContentResponse(c, content)
}

// GetShareFileContent 读取公开分享中的文本文件内容，保持分享密码校验逻辑。
func (h *Handler) GetShareFileContent(c *gin.Context) {
	code := c.Param("code")
	fileID := shareFileID(c)
	share, err := h.shareRepo.GetByCode(code)
	if err != nil || !share.IsActive {
		writeFileContentError(c, http.StatusNotFound, "分享不存在或已失效")
		return
	}

	if share.ExpireAt != nil && share.ExpireAt.Before(time.Now()) {
		writeFileContentError(c, http.StatusGone, "分享已过期")
		return
	}

	if share.Password != "" {
		if !h.sharePasswordGranted(c, share) {
			if !h.checkSharePasswordAttempt(c) {
				return
			}
			h.recordSharePasswordFailure(c)
			writeFileContentError(c, http.StatusUnauthorized, "需要密码验证")
			return
		}
	}

	// 校验 fid 归属；文件夹分享必须显式指定子文件（防 IDOR）。
	fileID, ok := shareContentFileID(share, fileID)
	if ok {
		fileID, ok = h.resolveShareFileID(c.Request.Context(), share, fileID)
	}
	if !ok {
		writeFileContentError(c, http.StatusNotFound, "分享不存在或已失效")
		return
	}

	content, err := h.loadFileContent(c.Request.Context(), fileID)
	if err != nil {
		writeFileContentLoadError(c, err)
		return
	}

	writeFileContentResponse(c, content)
}

func (h *Handler) loadFileContent(ctx context.Context, fileID string) ([]byte, error) {
	downloadURL, err := h.panClient.GetDownloadURLContext(ctx, fileID)
	if err != nil {
		return nil, fmt.Errorf("获取下载链接失败: %w", err)
	}
	return fetchRemoteFileContent(ctx, h.httpClient, downloadURL)
}

func fetchRemoteFileContent(ctx context.Context, client HTTPDoer, downloadURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建文件请求失败: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求云盘文件失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("云盘返回异常状态: %s", resp.Status)
	}
	if resp.ContentLength > maxTextPreviewBytes {
		return nil, errTextPreviewTooLarge
	}

	content, err := io.ReadAll(io.LimitReader(resp.Body, maxTextPreviewBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取云盘响应失败: %w", err)
	}
	if int64(len(content)) > maxTextPreviewBytes {
		return nil, errTextPreviewTooLarge
	}
	return content, nil
}

func writeFileContentLoadError(c *gin.Context, err error) {
	if errors.Is(err, errTextPreviewTooLarge) {
		writeFileContentError(c, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	writeFileContentError(c, http.StatusBadGateway, "读取文件内容失败: "+err.Error())
}

func writeFileContentResponse(c *gin.Context, content []byte) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, model.APIResponse{
		Code:    0,
		Message: "success",
		Data:    gin.H{"content_base64": base64.StdEncoding.EncodeToString(content)},
	})
}

func writeFileContentError(c *gin.Context, status int, message string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, model.APIResponse{Code: status, Message: message})
}

func proxyInlinePDF(c *gin.Context, client HTTPDoer, downloadURL string) {
	select {
	case pdfPreviewSlots <- struct{}{}:
		defer func() { <-pdfPreviewSlots }()
	default:
		writeFileContentError(c, http.StatusServiceUnavailable, "PDF 预览请求过多，请稍后再试")
		return
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, downloadURL, nil)
	if err != nil {
		writeFileContentError(c, http.StatusBadGateway, "创建 PDF 预览请求失败")
		return
	}
	if value := c.GetHeader("Range"); value != "" {
		if !validSingleByteRange(value) {
			writeFileContentError(c, http.StatusRequestedRangeNotSatisfiable, "仅支持单段字节范围")
			return
		}
		req.Header.Set("Range", value)
		if ifRange := c.GetHeader("If-Range"); ifRange != "" {
			req.Header.Set("If-Range", ifRange)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		writeFileContentError(c, http.StatusBadGateway, "请求 PDF 预览失败")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		if value := resp.Header.Get("Content-Range"); value != "" {
			c.Header("Content-Range", value)
		}
		c.Status(resp.StatusCode)
		c.Writer.WriteHeaderNow()
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		writeFileContentError(c, http.StatusBadGateway, "云盘返回异常状态: "+resp.Status)
		return
	}
	if !pdfResponseSizeAllowed(resp) {
		writeFileContentError(c, http.StatusRequestEntityTooLarge, "PDF 超过 100 MiB 预览上限")
		return
	}

	for _, header := range []string{"Accept-Ranges", "Content-Length", "Content-Range"} {
		if value := resp.Header.Get(header); value != "" {
			c.Header(header, value)
		}
	}
	c.Header("Cache-Control", "private, no-store")
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", "inline")
	c.Status(resp.StatusCode)
	_, _ = io.Copy(c.Writer, resp.Body)
}

func validSingleByteRange(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "bytes=") && len(value) > len("bytes=") && !strings.Contains(value, ",")
}

func pdfResponseSizeAllowed(resp *http.Response) bool {
	if resp.StatusCode == http.StatusOK {
		return resp.ContentLength >= 0 && resp.ContentLength <= maxPDFPreviewBytes
	}
	contentRange := resp.Header.Get("Content-Range")
	slash := strings.LastIndex(contentRange, "/")
	if slash < 0 || slash == len(contentRange)-1 {
		return false
	}
	total, err := strconv.ParseInt(contentRange[slash+1:], 10, 64)
	return err == nil && total >= 0 && total <= maxPDFPreviewBytes
}

func validCloudDownloadURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	return host == "ctyun.cn" || strings.HasSuffix(host, ".ctyun.cn") ||
		host == "mini189.cn" || strings.HasSuffix(host, ".mini189.cn")
}

func newPDFPreviewHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.DialContext = publicOnlyDialContext
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || !validCloudDownloadURL(req.URL.String()) {
				return errors.New("PDF 预览重定向地址不受信任")
			}
			return nil
		},
	}
}

func publicOnlyDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	for _, address := range addresses {
		ip := address.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return nil, errors.New("PDF 预览目标没有可用的公网地址")
}
