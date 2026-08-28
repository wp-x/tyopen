package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestFetchRemoteFileContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("电信云盘文本内容\n第二行"))
	}))
	defer server.Close()

	content, err := fetchRemoteFileContent(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("读取远程文本失败: %v", err)
	}
	if string(content) != "电信云盘文本内容\n第二行" {
		t.Fatalf("文本内容不匹配: %q", content)
	}
}

func TestFetchRemoteFileContentRejectsUpstreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	if _, err := fetchRemoteFileContent(context.Background(), server.Client(), server.URL); err == nil {
		t.Fatal("上游错误响应应返回错误")
	}
}

func TestFetchRemoteFileContentTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 20 * time.Millisecond}
	if _, err := fetchRemoteFileContent(context.Background(), client, server.URL); err == nil {
		t.Fatal("慢上游应触发 timeout")
	}
}

func TestFetchRemoteFileContentRejectsOversizedChunkedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		_, _ = w.Write(bytes.Repeat([]byte("x"), int(maxTextPreviewBytes)+1))
	}))
	defer server.Close()

	_, err := fetchRemoteFileContent(context.Background(), server.Client(), server.URL)
	if !errors.Is(err, errTextPreviewTooLarge) {
		t.Fatalf("超大文本应返回预览上限错误，实际为: %v", err)
	}
}

func TestWriteFileContentResponsePreservesArbitraryBytes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	original := []byte{0xff, 0xfe, 0x41, 0x00}

	writeFileContentResponse(ctx, original)
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("文本响应必须禁用缓存")
	}

	var response struct {
		Data struct {
			ContentBase64 string `json:"content_base64"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Data.ContentBase64)
	if err != nil {
		t.Fatalf("Base64 解码失败: %v", err)
	}
	if string(decoded) != string(original) {
		t.Fatalf("字节内容不匹配: %v", decoded)
	}
}

func TestProxyInlinePDFPreservesRangeAndForcesInline(t *testing.T) {
	var upstreamRange, upstreamIfRange string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRange = r.Header.Get("Range")
		upstreamIfRange = r.Header.Get("If-Range")
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Range", "bytes 0-3/8")
		w.Header().Set("Content-Disposition", "attachment; filename=file.pdf")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("%PDF"))
	}))
	defer server.Close()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/preview", nil)
	ctx.Request.Header.Set("Range", "bytes=0-3")
	ctx.Request.Header.Set("If-Range", `"etag"`)

	proxyInlinePDF(ctx, server.Client(), server.URL)

	if upstreamRange != "bytes=0-3" || upstreamIfRange != `"etag"` {
		t.Fatalf("范围头未完整转发: Range=%q If-Range=%q", upstreamRange, upstreamIfRange)
	}
	if recorder.Code != http.StatusPartialContent {
		t.Fatalf("状态码 = %d, want %d", recorder.Code, http.StatusPartialContent)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/pdf" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Content-Disposition"); got != "inline" {
		t.Fatalf("Content-Disposition = %q", got)
	}
	if got := recorder.Header().Get("Content-Range"); got != "bytes 0-3/8" {
		t.Fatalf("Content-Range = %q", got)
	}
	if recorder.Body.String() != "%PDF" {
		t.Fatalf("响应内容 = %q", recorder.Body.String())
	}
}

func TestProxyInlinePDFRejectsMultipleRangesBeforeUpstream(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/preview", nil)
	ctx.Request.Header.Set("Range", "bytes=0-1,4-5")
	proxyInlinePDF(ctx, server.Client(), server.URL)

	if recorder.Code != http.StatusRequestedRangeNotSatisfiable || called {
		t.Fatalf("复数 Range 应在请求上游前拒绝: code=%d called=%v", recorder.Code, called)
	}
}

func TestProxyInlinePDFPreservesUnsatisfiedRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes */8")
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	}))
	defer server.Close()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/preview", nil)
	proxyInlinePDF(ctx, server.Client(), server.URL)

	if recorder.Code != http.StatusRequestedRangeNotSatisfiable || recorder.Header().Get("Content-Range") != "bytes */8" {
		t.Fatalf("416 未正确透传: code=%d range=%q", recorder.Code, recorder.Header().Get("Content-Range"))
	}
}

func TestPDFResponseSizeAllowed(t *testing.T) {
	if pdfResponseSizeAllowed(&http.Response{StatusCode: http.StatusOK, ContentLength: maxPDFPreviewBytes + 1}) {
		t.Fatal("超大完整响应不应允许")
	}
	if pdfResponseSizeAllowed(&http.Response{StatusCode: http.StatusPartialContent, Header: http.Header{"Content-Range": {"bytes 0-3/104857601"}}}) {
		t.Fatal("总大小超限的范围响应不应允许")
	}
}

func TestValidCloudDownloadURL(t *testing.T) {
	for _, rawURL := range []string{"https://a.ctyun.cn/file", "https://x.mini189.cn/file"} {
		if !validCloudDownloadURL(rawURL) {
			t.Fatalf("合法云盘地址被拒绝: %s", rawURL)
		}
	}
	for _, rawURL := range []string{"http://a.ctyun.cn/file", "https://ctyun.cn.evil.test/file", "https://127.0.0.1/file"} {
		if validCloudDownloadURL(rawURL) {
			t.Fatalf("不可信地址被允许: %s", rawURL)
		}
	}
}
