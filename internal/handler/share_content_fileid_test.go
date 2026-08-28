package handler

import (
	"testing"
	"tyopen/internal/model"
)

func TestShareContentFileID(t *testing.T) {
	cases := []struct {
		name   string
		share  *model.Share
		fileID string
		wantID string
		wantOK bool
	}{
		{
			name:   "单文件分享省略 fid 时使用目标文件",
			share:  &model.Share{TargetType: "file", TargetID: "file-1"},
			wantID: "file-1",
			wantOK: true,
		},
		{
			name:   "文件夹分享省略 fid 时拒绝下载根目录",
			share:  &model.Share{TargetType: "folder", TargetID: "folder-1"},
			wantOK: false,
		},
		{
			name:   "文件夹分享以零表示根目录时拒绝下载",
			share:  &model.Share{TargetType: "folder", TargetID: "folder-1"},
			fileID: "0",
			wantOK: false,
		},
		{
			name:   "文件夹分享显式指定根目录时拒绝下载",
			share:  &model.Share{TargetType: "folder", TargetID: "folder-1"},
			fileID: "folder-1",
			wantOK: false,
		},
		{
			name:   "文件夹分享显式指定子文件时继续归属校验",
			share:  &model.Share{TargetType: "folder", TargetID: "folder-1"},
			fileID: "file-2",
			wantID: "file-2",
			wantOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotOK := shareContentFileID(tc.share, tc.fileID)
			if gotID != tc.wantID || gotOK != tc.wantOK {
				t.Fatalf("shareContentFileID() = (%q, %v), want (%q, %v)", gotID, gotOK, tc.wantID, tc.wantOK)
			}
		})
	}
}
