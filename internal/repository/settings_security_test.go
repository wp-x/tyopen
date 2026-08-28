package repository

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAdminPasswordHashAndTokenVersionAreAtomic(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "security.db")
	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	defer db.Close()

	repo := NewSettingsRepository(db.DB())
	hash, err := bcrypt.GenerateFromPassword([]byte("new-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	version, err := repo.UpdateAdminPasswordHashAndBump(string(hash))
	if err != nil {
		t.Fatalf("更新密码/版本失败: %v", err)
	}
	if version != 1 {
		t.Fatalf("版本错误：got=%d want=1", version)
	}
	settings, err := repo.Get()
	if err != nil {
		t.Fatalf("读取设置失败: %v", err)
	}
	if settings.AdminTokenVersion != 1 || settings.AdminPasswordHash == "" {
		t.Fatalf("密码/版本未持久化：version=%d hash=%q", settings.AdminTokenVersion, settings.AdminPasswordHash)
	}

	version, err = repo.BumpAdminTokenVersion()
	if err != nil || version != 2 {
		t.Fatalf("递增 token 版本失败：version=%d err=%v", version, err)
	}
}

func TestDatabasePermissionsAreRestricted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	dbPath := filepath.Join(dir, "tyopen.db")
	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}

	assertMode := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s 失败: %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s 权限错误：got=%#o want=%#o", path, got, want)
		}
	}
	assertMode(dir, 0700)
	assertMode(dbPath, 0600)
}
