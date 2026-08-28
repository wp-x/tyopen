package handler

import (
	"context"
	"errors"
	"tyopen/internal/model"
)

const (
	shareListPageStart = 1
	shareListPageSize  = 100
	maxShareListPages  = 100
	maxShareListItems  = 10000
)

func (h *Handler) listAllShareFiles(ctx context.Context, dirID string) ([]*model.FileInfo, error) {
	if dirID == "" {
		return nil, errors.New("缺少目录ID")
	}
	page := shareListPageStart
	files := make([]*model.FileInfo, 0, shareListPageSize)
	for page <= maxShareListPages {
		pageFiles, err := h.panClient.ListFilesContext(ctx, dirID, page, shareListPageSize)
		if err != nil {
			return nil, err
		}
		if len(pageFiles) == 0 {
			return files, nil
		}
		files = append(files, pageFiles...)
		if len(files) > maxShareListItems {
			return nil, errShareTreeTooLarge
		}
		if len(pageFiles) < shareListPageSize {
			return files, nil
		}
		page++
	}
	return nil, errShareTreeTooLarge
}
