package repository

import (
	"path/filepath"
	"sync"
	"testing"

	"tyopen/internal/model"
)

func newDownloadCountTestRepo(t *testing.T, maxDownloads int64) (*ShareRepository, func()) {
	t.Helper()
	db, err := NewDatabase(filepath.Join(t.TempDir(), "download-count.db"))
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	db.DB().SetMaxOpenConns(8)
	repo := NewShareRepository(db.DB())
	share := &model.Share{
		ShareCode:    "download-count",
		TargetType:   "file",
		TargetID:     "fid",
		TargetPath:   "/fid",
		TargetName:   "fid",
		IsActive:     true,
		MaxDownloads: maxDownloads,
	}
	if err := repo.Create(share); err != nil {
		_ = db.Close()
		t.Fatalf("创建分享失败: %v", err)
	}
	return repo, func() { _ = db.Close() }
}

func TestTryIncrementDownloadCountHonorsLimit(t *testing.T) {
	repo, cleanup := newDownloadCountTestRepo(t, 1)
	defer cleanup()

	if ok, err := repo.TryIncrementDownloadCount(1); err != nil || !ok {
		t.Fatalf("第一次扣减应成功，ok=%v err=%v", ok, err)
	}
	if ok, err := repo.TryIncrementDownloadCount(1); err != nil || ok {
		t.Fatalf("第二次扣减应被拒绝，ok=%v err=%v", ok, err)
	}

	share, err := repo.GetByID(1)
	if err != nil {
		t.Fatalf("读取分享失败: %v", err)
	}
	if share.DownloadCount != 1 {
		t.Fatalf("下载计数错误：got=%d want=1", share.DownloadCount)
	}
}

func TestTryIncrementDownloadCountIsAtomicUnderConcurrency(t *testing.T) {
	const attempts = 32
	repo, cleanup := newDownloadCountTestRepo(t, 1)
	defer cleanup()

	var wg sync.WaitGroup
	results := make(chan bool, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.TryIncrementDownloadCount(1)
			if err != nil {
				t.Errorf("并发扣减失败: %v", err)
				return
			}
			results <- ok
		}()
	}
	wg.Wait()
	close(results)

	var success int
	for ok := range results {
		if ok {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("并发时应只有一次成功：got=%d want=1", success)
	}
	share, err := repo.GetByID(1)
	if err != nil {
		t.Fatalf("读取分享失败: %v", err)
	}
	if share.DownloadCount != 1 {
		t.Fatalf("并发下载计数错误：got=%d want=1", share.DownloadCount)
	}
}

func TestTryIncrementDownloadCountUnlimited(t *testing.T) {
	repo, cleanup := newDownloadCountTestRepo(t, 0)
	defer cleanup()

	for i := 0; i < 5; i++ {
		if ok, err := repo.TryIncrementDownloadCount(1); err != nil || !ok {
			t.Fatalf("不限次数分享第 %d 次扣减失败：ok=%v err=%v", i+1, ok, err)
		}
	}
}
