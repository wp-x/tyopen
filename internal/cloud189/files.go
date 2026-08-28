package cloud189

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"tyopen/internal/model"
)

// listFilesResp 列目录响应（PC 与网页版 API 结构一致）
type listFilesResp struct {
	FileListAO struct {
		Count      int              `json:"count"`
		FileList   []listFileItem   `json:"fileList"`
		FolderList []listFolderItem `json:"folderList"`
	} `json:"fileListAO"`
}

type listFileItem struct {
	ID         json.RawMessage `json:"id"`
	Name       string          `json:"name"`
	Size       int64           `json:"size"`
	MD5        string          `json:"md5"`
	LastOpTime string          `json:"lastOpTime"`
	CreateDate string          `json:"createDate"`
}

type listFolderItem struct {
	ID         json.RawMessage `json:"id"`
	ParentID   json.RawMessage `json:"parentId"`
	Name       string          `json:"name"`
	LastOpTime string          `json:"lastOpTime"`
	CreateDate string          `json:"createDate"`
}

// ListFiles 获取文件列表（个人云）。dirID 为 "0" 或 "" 时视为根目录（-11）。
func (c *Client) ListFiles(dirID string, page, pageSize int) ([]*model.FileInfo, error) {
	return c.ListFilesContext(context.Background(), dirID, page, pageSize)
}

// ListFilesContext 获取文件列表并将调用方 context 传递到上游请求。
func (c *Client) ListFilesContext(ctx context.Context, dirID string, page, pageSize int) ([]*model.FileInfo, error) {
	if err := c.requireInitialized(); err != nil {
		return nil, err
	}
	return c.activeBackend().listFiles(ctx, dirID, page, pageSize)
}

// fileInfosFromList 列目录响应 → FileInfo 列表（目录在前），两种模式共用
func fileInfosFromList(resp *listFilesResp, dirID string) []*model.FileInfo {
	files := make([]*model.FileInfo, 0, len(resp.FileListAO.FolderList)+len(resp.FileListAO.FileList))
	for _, f := range resp.FileListAO.FolderList {
		id := rawJSONString(f.ID)
		parentID := rawJSONString(f.ParentID)
		if parentID == "" {
			parentID = dirID
		}
		files = append(files, &model.FileInfo{
			ID:       id,
			FID:      id, // 电信只有一个文件 ID 概念，FID 语义=文件自身 ID（前端契约沿用联通版）
			Name:     f.Name,
			Size:     0,
			IsDir:    true,
			ModTime:  parse189Time(f.LastOpTime, f.CreateDate),
			ParentID: parentID,
		})
	}
	for _, f := range resp.FileListAO.FileList {
		id := rawJSONString(f.ID)
		files = append(files, &model.FileInfo{
			ID:       id,
			FID:      id,
			Name:     f.Name,
			Size:     f.Size,
			IsDir:    false,
			ModTime:  parse189Time(f.LastOpTime, f.CreateDate),
			ParentID: dirID,
		})
	}
	return files
}

func (b *pcBackend) listFiles(ctx context.Context, dirID string, page, pageSize int) ([]*model.FileInfo, error) {
	c := b.c
	dirID = c.normalizeDirID(dirID)
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}

	body, err := c.request(ctx, http.MethodGet, apiURL+"/listFiles.action",
		map[string]string{
			"folderId":   dirID,
			"fileType":   "0",
			"mediaAttr":  "0",
			"iconOption": "5",
			"pageNum":    strconv.Itoa(page),
			"pageSize":   strconv.Itoa(pageSize),
			"recursive":  "0",
			"orderBy":    "filename",
			"descending": "false",
		}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("获取文件列表失败: %w", err)
	}

	var resp listFilesResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("解析文件列表失败: %w", err)
	}
	return fileInfosFromList(&resp, dirID), nil
}

// GetDownloadURL 获取文件下载直链。直链短时效，随用随取。
func (c *Client) GetDownloadURL(fileID string) (string, error) {
	return c.GetDownloadURLContext(context.Background(), fileID)
}

// GetDownloadURLContext 获取下载直链并将调用方 context 传递到上游请求。
func (c *Client) GetDownloadURLContext(ctx context.Context, fileID string) (string, error) {
	if err := c.requireInitialized(); err != nil {
		return "", err
	}
	return c.activeBackend().getDownloadURL(ctx, fileID)
}

func (b *pcBackend) getDownloadURL(ctx context.Context, fileID string) (string, error) {
	c := b.c
	body, err := c.request(ctx, http.MethodGet, apiURL+"/getFileDownloadUrl.action",
		map[string]string{
			"fileId": fileID,
			"dt":     "3",
			"flag":   "1",
		}, nil, nil)
	if err != nil {
		return "", fmt.Errorf("获取下载链接失败: %w", err)
	}
	var resp struct {
		FileDownloadURL string `json:"fileDownloadUrl"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("解析下载链接失败: %w", err)
	}
	if resp.FileDownloadURL == "" {
		return "", fmt.Errorf("获取下载链接失败: 响应缺少 fileDownloadUrl")
	}

	downloadURL := strings.ReplaceAll(resp.FileDownloadURL, "&amp;", "&")
	downloadURL = strings.Replace(downloadURL, "http://", "https://", 1)
	return followDownloadRedirect(ctx, downloadURL, "")
}

// followDownloadRedirect 禁止重定向地 GET 一次，若 302 取 Location 作为最终直链。
// cookie 非空时携带（网页版 downloadFile.action 必须带 Cookie 才会 302）。
// 若上游返回错误（HTTP 4xx/5xx 或错误 JSON/XML），返回明确错误而不是透传坏链接。
func followDownloadRedirect(ctx context.Context, downloadURL, cookie string) (string, error) {
	noRedirect := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", fmt.Errorf("解析最终下载链接失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusSeeOther {
		_, _ = io.Copy(io.Discard, resp.Body)
		if loc := resp.Header.Get("Location"); loc != "" {
			return loc, nil
		}
		return "", fmt.Errorf("解析最终下载链接失败: 上游返回 %d 但缺少 Location", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("下载链接不可用: %s", downloadErrorMessage(resp.StatusCode, body))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return downloadURL, nil
}

// downloadErrorMessage 从上游错误响应（JSON 或 XML）里提取可读错误信息
func downloadErrorMessage(status int, body []byte) string {
	s := string(body)
	// JSON：{"errorCode":"...","errorMsg":"..."} 或 {"res_code":...,"res_message":"..."}
	var jsonErr struct {
		ErrorCode  string          `json:"errorCode"`
		ErrorMsg   string          `json:"errorMsg"`
		ResCode    json.RawMessage `json:"res_code"`
		ResMessage string          `json:"res_message"`
	}
	if err := json.Unmarshal(body, &jsonErr); err == nil {
		if jsonErr.ErrorMsg != "" {
			return fmt.Sprintf("%s (%s)", jsonErr.ErrorMsg, jsonErr.ErrorCode)
		}
		if jsonErr.ResMessage != "" {
			return jsonErr.ResMessage
		}
	}
	// XML：<Code>FileNotFound</Code><Message>...</Message>
	if code := xmlTagValue(s, "Code"); code != "" {
		if msg := xmlTagValue(s, "Message"); msg != "" {
			return fmt.Sprintf("%s (%s)", msg, code)
		}
		return code
	}
	return fmt.Sprintf("HTTP %d: %s", status, truncate(s, 200))
}

// xmlTagValue 提取 XML 标签内容（简单实现，足够应对错误响应）
func xmlTagValue(s, tag string) string {
	start := strings.Index(s, "<"+tag+">")
	end := strings.Index(s, "</"+tag+">")
	if start < 0 || end < 0 || end <= start {
		return ""
	}
	return s[start+len(tag)+2 : end]
}

// CreateDirectory 创建目录
func (c *Client) CreateDirectory(parentID, dirName string) (*model.FileInfo, error) {
	return c.CreateDirectoryCtx(context.Background(), parentID, dirName)
}

// CreateDirectoryCtx 创建目录（支持 context）
func (c *Client) CreateDirectoryCtx(ctx context.Context, parentID, dirName string) (*model.FileInfo, error) {
	if err := c.requireInitialized(); err != nil {
		return nil, err
	}
	return c.activeBackend().createDirectory(ctx, parentID, dirName)
}

func (b *pcBackend) createDirectory(ctx context.Context, parentID, dirName string) (*model.FileInfo, error) {
	c := b.c
	parentID = c.normalizeDirID(parentID)

	body, err := c.request(ctx, http.MethodPost, apiURL+"/createFolder.action",
		map[string]string{
			"folderName":     dirName,
			"relativePath":   "",
			"parentFolderId": parentID,
		}, nil, url.Values{})
	if err != nil {
		return nil, fmt.Errorf("创建目录失败: %w", err)
	}

	return dirInfoFromCreateResp(body, parentID, dirName), nil
}

// dirInfoFromCreateResp 解析 createFolder 响应（两种模式共用，字段缺失时降级用入参）
func dirInfoFromCreateResp(body []byte, parentID, dirName string) *model.FileInfo {
	var resp struct {
		ID   json.RawMessage `json:"id"`
		Name string          `json:"name"`
	}
	_ = json.Unmarshal(body, &resp)

	name := resp.Name
	if name == "" {
		name = dirName
	}
	id := rawJSONString(resp.ID)
	return &model.FileInfo{
		ID:       id,
		FID:      id,
		Name:     name,
		Size:     0,
		IsDir:    true,
		ModTime:  time.Now(),
		ParentID: parentID,
	}
}

// Rename 重命名文件/目录（个人云）
func (c *Client) Rename(ctx context.Context, isDir bool, id, newName string) error {
	if err := c.requireInitialized(); err != nil {
		return err
	}
	return c.activeBackend().rename(ctx, isDir, id, newName)
}

func (b *pcBackend) rename(ctx context.Context, isDir bool, id, newName string) error {
	var query map[string]string
	var endpoint string
	if isDir {
		endpoint = "/renameFolder.action"
		query = map[string]string{"folderId": id, "destFolderName": newName}
	} else {
		endpoint = "/renameFile.action"
		query = map[string]string{"fileId": id, "destFileName": newName}
	}
	_, err := b.c.request(ctx, http.MethodPost, apiURL+endpoint, query, nil, url.Values{})
	if err != nil {
		return fmt.Errorf("重命名失败: %w", err)
	}
	return nil
}

// parse189Time 兼容电信接口的多种时间格式（可能带 U+202F/U+00A0）
func parse189Time(values ...string) time.Time {
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05",
		"Jan 2, 2006, 3:04:05 PM",
		"Jan 2, 2006 3:04:05 PM",
		"20060102150405",
		time.RFC3339,
	}
	for _, v := range values {
		s := strings.TrimSpace(v)
		s = strings.ReplaceAll(s, " ", " ") // U+202F 窄不换行空格
		s = strings.ReplaceAll(s, " ", " ") // U+00A0 不换行空格
		if s == "" {
			continue
		}
		for _, layout := range layouts {
			if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
