package cloud189

import (
	"context"
	"encoding/hex"
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

// webSliceSize 网页版上传分片固定 10MiB
const webSliceSize = defaultSliceSize

// upload 网页版上传：sessionKey+每请求随机 AES key，hex 全部小写。
// initMultiUpload（带 fileMd5+sliceMd5 支持秒传）→ getMultiUploadUrls → PUT 分片 → commit
func (b *webBackend) upload(ctx context.Context, parentID, fileName string, size int64, seeker io.ReadSeeker, onProgress func(uploaded, total int64)) (*model.FileInfo, error) {
	// 每次上传前刷新 sessionKey
	if err := b.refreshSessionKey(ctx); err != nil {
		return nil, err
	}

	md5s, err := computeMD5s(seeker, size, webSliceSize)
	if err != nil {
		return nil, fmt.Errorf("计算文件MD5失败: %w", err)
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("重置上传流失败: %w", err)
	}

	// 网页版 MD5 用小写 HEX（与 PC 模式大写不同，拼接规则相同）
	fileMd5 := strings.ToLower(md5s.fileMD5)
	sliceMd5 := strings.ToLower(md5s.sliceMD5)

	reportProgress := func(uploaded int64) {
		if onProgress != nil {
			onProgress(uploaded, size)
		}
	}

	// 1. initMultiUpload（带 fileMd5+sliceMd5，支持秒传）
	res, err := b.uploadRequest(ctx, "/person/initMultiUpload", map[string]string{
		"parentFolderId": parentID,
		"fileName":       url.QueryEscape(fileName),
		"fileSize":       strconv.FormatInt(size, 10),
		"sliceSize":      strconv.FormatInt(webSliceSize, 10),
		"fileMd5":        fileMd5,
		"sliceMd5":       sliceMd5,
	})
	if err != nil {
		return nil, fmt.Errorf("初始化上传失败: %w", err)
	}
	uploadFileID := jsonStringAt(res, "data", "uploadFileId")
	if uploadFileID == "" {
		return nil, fmt.Errorf("初始化上传失败: 响应缺少 uploadFileId")
	}
	fileDataExists := jsonIntAt(res, "data", "fileDataExists")

	if fileDataExists != 1 {
		// 2+3. 逐片获取上传地址并 PUT（header 用 requestHeader 原样拆解，不加额外参数）
		var uploaded int64
		for i := range md5s.slices {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			partNo := i + 1
			partSize := webSliceSize
			if remain := size - int64(i)*webSliceSize; remain < partSize {
				partSize = remain
			}

			urlsRes, err := b.uploadRequest(ctx, "/person/getMultiUploadUrls", map[string]string{
				"partInfo":     fmt.Sprintf("%d-%s", partNo, md5s.slices[i].base64),
				"uploadFileId": uploadFileID,
			})
			if err != nil {
				return nil, fmt.Errorf("获取第 %d 片上传地址失败: %w", partNo, err)
			}
			var urlsResp struct {
				UploadURLs map[string]struct {
					RequestURL    string `json:"requestURL"`
					RequestHeader string `json:"requestHeader"`
				} `json:"uploadUrls"`
			}
			if err := json.Unmarshal(urlsRes, &urlsResp); err != nil {
				return nil, fmt.Errorf("获取第 %d 片上传地址失败: 解析响应失败: %w", partNo, err)
			}
			part, ok := urlsResp.UploadURLs[fmt.Sprintf("partNumber_%d", partNo)]
			if !ok || part.RequestURL == "" {
				return nil, fmt.Errorf("获取第 %d 片上传地址失败: 响应缺少上传地址", partNo)
			}

			// 单片最多尝试 2 次，每次重新定位分片起点
			const partAttempts = 2
			var partErr error
			for attempt := 0; attempt < partAttempts; attempt++ {
				if _, err := seeker.Seek(int64(i)*webSliceSize, io.SeekStart); err != nil {
					return nil, fmt.Errorf("定位上传分片失败: %w", err)
				}
				pr := &progressReader{
					r: io.LimitReader(seeker, partSize),
					onRead: func(n int64) {
						reportProgress(uploaded + n)
					},
				}
				if partErr = b.putSlice(ctx, part.RequestURL, part.RequestHeader, pr, partSize); partErr == nil {
					break
				}
			}
			if partErr != nil {
				return nil, fmt.Errorf("上传第 %d 片失败: %w", partNo, partErr)
			}
			uploaded += partSize
			reportProgress(uploaded)
		}
	}

	// 4. commitMultiUploadFile（秒传与普通上传参数相同）
	commitBody, err := b.uploadRequest(ctx, "/person/commitMultiUploadFile", map[string]string{
		"uploadFileId": uploadFileID,
		"fileMd5":      fileMd5,
		"sliceMd5":     sliceMd5,
		"lazyCheck":    "1",
		"opertype":     "3",
	})
	if err != nil {
		return nil, fmt.Errorf("提交上传失败: %w", err)
	}
	fileInfo, err := fileInfoFromCommitResp(commitBody, parentID, fileName, size)
	if err != nil {
		// 网页版 commit 响应结构未文档化，拿不到 fileId 时降级返回基本信息
		fileInfo = &model.FileInfo{
			Name:     fileName,
			Size:     size,
			IsDir:    false,
			ModTime:  time.Now(),
			ParentID: parentID,
		}
	}

	reportProgress(size)
	return fileInfo, nil
}

// uploadRequest 网页版上传请求模板：每请求随机 AES key l（16~32 字符），
// form 原文 AES-128-ECB 加密（key=l[:16]）小写 HEX 作为 params；
// 签名 HMAC-SHA1(secret=l) 小写 HEX；头带 SessionKey/Signature/X-Request-Date/
// X-Request-ID/EncryptionText(RSA加密l,base64)/PkId。
func (b *webBackend) uploadRequest(ctx context.Context, uri string, form map[string]string) ([]byte, error) {
	date := strconv.FormatInt(time.Now().UnixMilli(), 10)
	requestID := randomPattern("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx")
	l := randomPattern("xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx")
	l = l[:randKeyLength()]

	encrypted, err := aesECBEncrypt([]byte(encodeWebForm(form)), []byte(l[:16]))
	if err != nil {
		return nil, fmt.Errorf("加密请求参数失败: %w", err)
	}
	params := hex.EncodeToString(encrypted) // 小写

	sessionKey := b.getSessionKey()
	if sessionKey == "" {
		if err := b.refreshSessionKey(ctx); err != nil {
			return nil, err
		}
		sessionKey = b.getSessionKey()
	}
	signature := hmacSha1Lower(fmt.Sprintf("SessionKey=%s&Operate=GET&RequestURI=%s&Date=%s&params=%s",
		sessionKey, uri, date, params), l)

	pubKey, pkID, err := b.getRsaKey(ctx)
	if err != nil {
		return nil, err
	}
	encryptionText, err := rsaEncryptBase64(pubKey, []byte(l))
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uploadURL+uri+"?params="+params, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json;charset=UTF-8")
	req.Header.Set("SessionKey", sessionKey)
	req.Header.Set("Signature", signature)
	req.Header.Set("X-Request-Date", date)
	req.Header.Set("X-Request-ID", requestID)
	req.Header.Set("EncryptionText", encryptionText)
	req.Header.Set("PkId", pkID)
	req.Header.Set("Cookie", b.c.getCookie())

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var head struct {
		Code string `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return nil, fmt.Errorf("解析上传响应失败: %w", err)
	}
	if head.Code != "SUCCESS" {
		return nil, fmt.Errorf("%s: %s", uri, head.Msg)
	}
	return body, nil
}

// putSlice 网页版 PUT 分片：requestURL 绝对地址，header 用 requestHeader 原样拆解
// （先 URL 反转义），不追加任何额外参数与签名头
func (b *webBackend) putSlice(ctx context.Context, requestURL, requestHeader string, body io.Reader, size int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, requestURL, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	decoded, err := url.PathUnescape(requestHeader)
	if err != nil {
		decoded = requestHeader
	}
	for _, kv := range strings.Split(decoded, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
}

// jsonStringAt 从 JSON 里按路径取字符串字段（兼容数字/字符串两种类型）
func jsonStringAt(body []byte, path ...string) string {
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	for _, p := range path {
		m, ok := v.(map[string]interface{})
		if !ok {
			return ""
		}
		v = m[p]
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	}
	return ""
}

// jsonIntAt 从 JSON 里按路径取整数字段
func jsonIntAt(body []byte, path ...string) int {
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return 0
	}
	for _, p := range path {
		m, ok := v.(map[string]interface{})
		if !ok {
			return 0
		}
		v = m[p]
	}
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}
