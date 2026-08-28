package cloud189

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"tyopen/internal/model"
)

// listFiles 网页版列目录：GET /api/open/file/listFiles.action
func (b *webBackend) listFiles(dirID string, page, pageSize int) ([]*model.FileInfo, error) {
	dirID = b.c.normalizeDirID(dirID)
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 60
	}

	body, err := b.request(context.Background(), http.MethodGet, webURL+"/api/open/file/listFiles.action",
		map[string]string{
			"pageSize":   strconv.Itoa(pageSize),
			"pageNum":    strconv.Itoa(page),
			"mediaType":  "0",
			"folderId":   dirID,
			"iconOption": "5",
			"orderBy":    "lastOpTime",
			"descending": "true",
		}, nil)
	if err != nil {
		return nil, fmt.Errorf("获取文件列表失败: %w", err)
	}

	var resp listFilesResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("解析文件列表失败: %w", err)
	}
	return fileInfosFromList(&resp, dirID), nil
}

// getDownloadURL 网页版下载直链：getFileInfo → downloadUrl → 手动跟随 302 取 Location
func (b *webBackend) getDownloadURL(fileID string) (string, error) {
	body, err := b.request(context.Background(), http.MethodGet, webURL+"/api/portal/getFileInfo.action",
		map[string]string{"fileId": fileID}, nil)
	if err != nil {
		return "", fmt.Errorf("获取下载链接失败: %w", err)
	}
	var resp struct {
		DownloadURL string `json:"downloadUrl"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("解析下载链接失败: %w", err)
	}
	if resp.DownloadURL == "" {
		return "", fmt.Errorf("获取下载链接失败: 响应缺少 downloadUrl")
	}

	downloadURL := strings.ReplaceAll(resp.DownloadURL, "&amp;", "&")
	if strings.HasPrefix(downloadURL, "//") {
		downloadURL = "https:" + downloadURL
	}
	finalURL, err := followDownloadRedirect(downloadURL, b.c.getCookie())
	if err != nil {
		return "", err
	}
	return strings.Replace(finalURL, "http://", "https://", 1), nil
}

// createDirectory 网页版新建目录：POST /api/open/file/createFolder.action
func (b *webBackend) createDirectory(ctx context.Context, parentID, dirName string) (*model.FileInfo, error) {
	parentID = b.c.normalizeDirID(parentID)
	body, err := b.request(ctx, http.MethodPost, webURL+"/api/open/file/createFolder.action",
		nil, url.Values{
			"parentFolderId": {parentID},
			"folderName":     {dirName},
		})
	if err != nil {
		return nil, fmt.Errorf("创建目录失败: %w", err)
	}
	return dirInfoFromCreateResp(body, parentID, dirName), nil
}

// rename 网页版重命名：POST /api/open/file/renameFile|renameFolder.action
func (b *webBackend) rename(ctx context.Context, isDir bool, id, newName string) error {
	var endpoint string
	var form url.Values
	if isDir {
		endpoint = "/api/open/file/renameFolder.action"
		form = url.Values{"folderId": {id}, "destFolderName": {newName}}
	} else {
		endpoint = "/api/open/file/renameFile.action"
		form = url.Values{"fileId": {id}, "destFileName": {newName}}
	}
	_, err := b.request(ctx, http.MethodPost, webURL+endpoint, nil, form)
	if err != nil {
		return fmt.Errorf("重命名失败: %w", err)
	}
	return nil
}

// getFileName 网页版：GET /api/portal/getFileInfo.action?fileId= → fileName（文件/目录均可）
func (b *webBackend) getFileName(ctx context.Context, id string) (string, error) {
	body, err := b.request(ctx, http.MethodGet, webURL+"/api/portal/getFileInfo.action",
		map[string]string{"fileId": id}, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		FileName string `json:"fileName"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("解析文件信息失败: %w", err)
	}
	if resp.FileName == "" {
		return "", fmt.Errorf("解析文件信息失败: 响应缺少 fileName")
	}
	return resp.FileName, nil
}

// runBatch 网页版批量任务：POST /api/open/batch/createBatchTask.action + checkBatchTask 轮询
func (b *webBackend) runBatch(ctx context.Context, taskType string, isDir bool, ids []string, names map[string]string, targetDirID string) error {
	taskInfos, err := buildTaskInfos(isDir, ids, names)
	if err != nil {
		return err
	}

	targetFolderID := ""
	if taskType != batchTypeDelete {
		targetFolderID = b.c.normalizeDirID(targetDirID)
	}

	body, err := b.request(ctx, http.MethodPost, webURL+"/api/open/batch/createBatchTask.action",
		nil, url.Values{
			"type":           {taskType},
			"targetFolderId": {targetFolderID},
			"taskInfos":      {taskInfos},
		})
	if err != nil {
		return fmt.Errorf("创建批量任务失败: %w", err)
	}
	var createResp struct {
		TaskID string `json:"taskId"`
	}
	if err := json.Unmarshal(body, &createResp); err != nil || createResp.TaskID == "" {
		return fmt.Errorf("创建批量任务失败: 响应缺少 taskId")
	}

	return b.waitBatchTask(ctx, taskType, createResp.TaskID)
}

// waitBatchTask 轮询批量任务直到完成（taskStatus: 1 初始化 2 冲突 3 执行中 4 完成）
func (b *webBackend) waitBatchTask(ctx context.Context, taskType, taskID string) error {
	deadline := time.Now().Add(batchPollTimeout)
	for {
		body, err := b.request(ctx, http.MethodPost, webURL+"/api/open/batch/checkBatchTask.action",
			nil, url.Values{
				"type":   {taskType},
				"taskId": {taskID},
			})
		if err != nil {
			return fmt.Errorf("查询批量任务失败: %w", err)
		}
		status, failedMessage, err := parseBatchTaskStatus(body)
		if err != nil {
			return err
		}
		switch status {
		case 4:
			return nil
		case 2:
			return fmt.Errorf("批量任务冲突: %s", failedMessage)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("批量任务超时（%v 内未完成）", batchPollTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(batchPollInterval):
		}
	}
}
