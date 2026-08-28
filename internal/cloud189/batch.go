package cloud189

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// batch 任务类型
const (
	batchTypeMove   = "MOVE"
	batchTypeCopy   = "COPY"
	batchTypeDelete = "DELETE"
)

// batchTaskInfo taskInfos 元素
type batchTaskInfo struct {
	FileID   string `json:"fileId"`
	FileName string `json:"fileName"`
	IsFolder int    `json:"isFolder"` // 0 文件 / 1 目录
}

const (
	batchPollInterval = 500 * time.Millisecond
	batchPollTimeout  = 120 * time.Second
)

// Delete 删除文件/目录（个人云）
func (c *Client) Delete(ctx context.Context, isDir bool, id string) error {
	return c.DeleteBatch(ctx, isDir, []string{id})
}

// DeleteBatch 批量删除文件/目录（个人云，同类型一批）
func (c *Client) DeleteBatch(ctx context.Context, isDir bool, ids []string) error {
	return c.runBatchTask(ctx, batchTypeDelete, isDir, ids, "")
}

// Move 移动文件/目录到目标目录（个人云）
func (c *Client) Move(ctx context.Context, isDir bool, id, targetDirID string) error {
	return c.MoveBatch(ctx, isDir, []string{id}, targetDirID)
}

// MoveBatch 批量移动文件/目录到目标目录（个人云，同类型一批）
func (c *Client) MoveBatch(ctx context.Context, isDir bool, ids []string, targetDirID string) error {
	return c.runBatchTask(ctx, batchTypeMove, isDir, ids, targetDirID)
}

// Copy 复制文件/目录到目标目录（个人云）
func (c *Client) Copy(ctx context.Context, isDir bool, id, targetDirID string) error {
	return c.CopyBatch(ctx, isDir, []string{id}, targetDirID)
}

// CopyBatch 批量复制文件/目录到目标目录（个人云，同类型一批）
func (c *Client) CopyBatch(ctx context.Context, isDir bool, ids []string, targetDirID string) error {
	return c.runBatchTask(ctx, batchTypeCopy, isDir, ids, targetDirID)
}

// runBatchTask createBatchTask + checkBatchTask 轮询直到 taskStatus=4
func (c *Client) runBatchTask(ctx context.Context, taskType string, isDir bool, ids []string, targetDirID string) error {
	if err := c.requireInitialized(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	backend := c.activeBackend()
	// MOVE/COPY 的 taskInfos 必须带真实文件名，否则上游任务永远停在 taskStatus=1；
	// DELETE 空文件名可正常完成，保持原样。
	var names map[string]string
	if taskType != batchTypeDelete {
		names = make(map[string]string, len(ids))
		for _, id := range ids {
			// 逐个解析（数量通常很小）；失败降级为空名（保持旧行为）
			if name, err := backend.getFileName(ctx, id); err == nil && name != "" {
				names[id] = name
			}
		}
	}
	return backend.runBatch(ctx, taskType, isDir, ids, names, targetDirID)
}

// buildTaskInfos 组装 taskInfos（targetFolderId 由调用方按模式处理）
func buildTaskInfos(isDir bool, ids []string, names map[string]string) (string, error) {
	isFolder := 0
	if isDir {
		isFolder = 1
	}
	infos := make([]batchTaskInfo, 0, len(ids))
	for _, id := range ids {
		infos = append(infos, batchTaskInfo{FileID: id, FileName: names[id], IsFolder: isFolder})
	}
	taskInfosJSON, err := json.Marshal(infos)
	if err != nil {
		return "", err
	}
	return string(taskInfosJSON), nil
}

// getFileName PC 模式：GET {apiURL}/getFileInfo.action?fileId= → name（文件/目录均可）
func (b *pcBackend) getFileName(ctx context.Context, id string) (string, error) {
	body, err := b.c.request(ctx, http.MethodGet, apiURL+"/getFileInfo.action",
		map[string]string{"fileId": id}, nil, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("解析文件信息失败: %w", err)
	}
	if resp.Name == "" {
		return "", fmt.Errorf("解析文件信息失败: 响应缺少 name")
	}
	return resp.Name, nil
}

func (b *pcBackend) runBatch(ctx context.Context, taskType string, isDir bool, ids []string, names map[string]string, targetDirID string) error {
	c := b.c
	taskInfos, err := buildTaskInfos(isDir, ids, names)
	if err != nil {
		return err
	}

	targetFolderID := ""
	if taskType != batchTypeDelete {
		targetFolderID = c.normalizeDirID(targetDirID)
	}

	body, err := c.request(ctx, http.MethodPost, apiURL+"/batch/createBatchTask.action",
		nil, nil, url.Values{
			"type":           {taskType},
			"taskInfos":      {taskInfos},
			"targetFolderId": {targetFolderID},
			"targetFileName": {""},
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
func (b *pcBackend) waitBatchTask(ctx context.Context, taskType, taskID string) error {
	deadline := time.Now().Add(batchPollTimeout)
	for {
		body, err := b.c.request(ctx, http.MethodPost, apiURL+"/batch/checkBatchTask.action",
			nil, nil, url.Values{
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

// parseBatchTaskStatus 解析 checkBatchTask 响应（两种模式共用）
func parseBatchTaskStatus(body []byte) (status int, failedMessage string, err error) {
	var checkResp struct {
		TaskStatus    int    `json:"taskStatus"`
		FailedMessage string `json:"failedMessage"`
	}
	if err := json.Unmarshal(body, &checkResp); err != nil {
		return 0, "", fmt.Errorf("查询批量任务失败: 解析响应失败: %w", err)
	}
	return checkResp.TaskStatus, checkResp.FailedMessage, nil
}
