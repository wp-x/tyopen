package cloud189

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"tyopen/internal/model"
)

const defaultSliceSize int64 = 10 * 1024 * 1024 // 10MiB

// sliceSizeFor 分片大小规则（PC 协议，文档第 7 节）
func sliceSizeFor(size int64) int64 {
	if size <= defaultSliceSize*999 {
		return defaultSliceSize
	}
	if size <= defaultSliceSize*2*999 {
		return defaultSliceSize * 2
	}
	// 更大：ceil(size/1999/10MiB) 倍率（最小 5）* 10MiB
	mult := (size + 1999*defaultSliceSize - 1) / (1999 * defaultSliceSize)
	if mult < 5 {
		mult = 5
	}
	return mult * defaultSliceSize
}

// sliceMD5 单片 MD5（大写 HEX + base64 原始字节）
type sliceMD5 struct {
	hexUpper string
	base64   string
}

// fileMD5Result 整文件与分片 MD5 计算结果
type fileMD5Result struct {
	fileMD5  string // 整文件 MD5 大写 HEX
	sliceMD5 string // 单片时等于 fileMD5，多片时 MD5(各片MD5hex用"\n"拼接) 大写 HEX
	slices   []sliceMD5
}

// UploadFile 上传文件到指定目录（按当前认证模式分派 PC/网页版协议）
func (c *Client) UploadFile(ctx context.Context, parentID, fileName, contentType string, size int64, content io.Reader, onProgress func(uploaded, total int64)) (*model.FileInfo, error) {
	if err := c.requireInitialized(); err != nil {
		return nil, err
	}
	parentID = c.normalizeDirID(parentID)

	// content 是 io.Reader，需要可重复读取（算 MD5 + 分片上传）：
	// 已是 ReadSeeker 直接用，否则落临时文件。
	var seeker io.ReadSeeker
	var tmpPath string
	if rs, ok := content.(io.ReadSeeker); ok {
		seeker = rs
	} else {
		tmp, err := TempFileUploader("cloud189-upload-*")
		if err != nil {
			return nil, fmt.Errorf("创建上传临时文件失败: %w", err)
		}
		tmpPath = tmp.Name()
		defer func() {
			tmp.Close()
			os.Remove(tmpPath)
		}()
		written, err := io.Copy(tmp, content)
		if err != nil {
			return nil, fmt.Errorf("写入上传临时文件失败: %w", err)
		}
		if size <= 0 {
			size = written
		}
		seeker = tmp
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("重置上传流失败: %w", err)
	}

	return c.activeBackend().upload(ctx, parentID, fileName, size, seeker, onProgress)
}

// upload PC 协议上传：initMultiUpload → 分片 PUT → commit（opertype=3 覆盖）
func (b *pcBackend) upload(ctx context.Context, parentID, fileName string, size int64, seeker io.ReadSeeker, onProgress func(uploaded, total int64)) (*model.FileInfo, error) {
	c := b.c
	sliceSize := sliceSizeFor(size)

	// 单次顺序读取，同时算整文件 MD5 与各分片 MD5
	md5s, err := computeMD5s(seeker, size, sliceSize)
	if err != nil {
		return nil, fmt.Errorf("计算文件MD5失败: %w", err)
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("重置上传流失败: %w", err)
	}

	reportProgress := func(uploaded int64) {
		if onProgress != nil {
			onProgress(uploaded, size)
		}
	}

	// 1. initMultiUpload（带 fileMd5+sliceMd5，支持秒传）
	aesParams := map[string]string{
		"parentFolderId": parentID,
		"fileName":       url.QueryEscape(fileName),
		"fileSize":       strconv.FormatInt(size, 10),
		"sliceSize":      strconv.FormatInt(sliceSize, 10),
		"lazyCheck":      "1",
		"fileMd5":        md5s.fileMD5,
		"sliceMd5":       md5s.sliceMD5,
	}
	body, err := c.request(ctx, http.MethodGet, uploadURL+"/person/initMultiUpload", nil, aesParams, nil)
	if err != nil {
		return nil, fmt.Errorf("初始化上传失败: %w", err)
	}
	var initResp struct {
		Data struct {
			UploadType     int             `json:"uploadType"`
			UploadHost     string          `json:"uploadHost"`
			UploadFileID   json.RawMessage `json:"uploadFileId"`
			FileDataExists int             `json:"fileDataExists"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &initResp); err != nil {
		return nil, fmt.Errorf("初始化上传失败: 解析响应失败: %w", err)
	}
	uploadFileID := rawJSONString(initResp.Data.UploadFileID)
	if uploadFileID == "" {
		return nil, fmt.Errorf("初始化上传失败: 响应缺少 uploadFileId")
	}
	uploadHost := initResp.Data.UploadHost
	if uploadHost == "" {
		uploadHost = uploadURL
	}

	if initResp.Data.FileDataExists != 1 {
		// 2. getMultiUploadUrls
		partInfos := make([]string, 0, len(md5s.slices))
		for i, s := range md5s.slices {
			partInfos = append(partInfos, fmt.Sprintf("%d-%s", i+1, s.base64))
		}
		urlsBody, err := c.request(ctx, http.MethodGet, uploadURL+"/person/getMultiUploadUrls", nil,
			map[string]string{
				"uploadFileId": uploadFileID,
				"partInfo":     strings.Join(partInfos, ","),
			}, nil)
		if err != nil {
			return nil, fmt.Errorf("获取上传地址失败: %w", err)
		}
		var urlsResp struct {
			UploadURLs map[string]struct {
				RequestURL    string `json:"requestURL"`
				RequestHeader string `json:"requestHeader"`
			} `json:"uploadUrls"`
		}
		if err := json.Unmarshal(urlsBody, &urlsResp); err != nil {
			return nil, fmt.Errorf("获取上传地址失败: 解析响应失败: %w", err)
		}

		// 3. 逐片 PUT（原始字节；header 用 requestHeader 原样拆解；URL 追加 clientSuffix，不加签名头）
		var uploaded int64
		for i := range md5s.slices {
			partNo := i + 1
			part, ok := urlsResp.UploadURLs[fmt.Sprintf("partNumber_%d", partNo)]
			if !ok || part.RequestURL == "" {
				return nil, fmt.Errorf("获取上传地址失败: 缺少第 %d 片的上传地址", partNo)
			}
			partSize := sliceSize
			if remain := size - int64(i)*sliceSize; remain < partSize {
				partSize = remain
			}
			// 单片最多尝试 2 次，每次重新定位分片起点并构造新的进度 reader
			const partAttempts = 2
			var partErr error
			for attempt := 0; attempt < partAttempts; attempt++ {
				if _, err := seeker.Seek(int64(i)*sliceSize, io.SeekStart); err != nil {
					return nil, fmt.Errorf("定位上传分片失败: %w", err)
				}
				pr := &progressReader{
					r: io.LimitReader(seeker, partSize),
					onRead: func(n int64) {
						reportProgress(uploaded + n)
					},
				}
				if partErr = b.putSlice(ctx, uploadHost, part.RequestURL, part.RequestHeader, pr, partSize); partErr == nil {
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

	// 4. commitMultiUploadFile（opertype=3 覆盖；秒传只传 uploadFileId, isLog, opertype）
	commitParams := map[string]string{
		"uploadFileId": uploadFileID,
		"isLog":        "0",
		"opertype":     "3",
	}
	if initResp.Data.FileDataExists != 1 {
		commitParams["fileMd5"] = md5s.fileMD5
		commitParams["sliceMd5"] = md5s.sliceMD5
		commitParams["lazyCheck"] = "1"
	}
	commitBody, err := c.request(ctx, http.MethodGet, uploadURL+"/person/commitMultiUploadFile", nil, commitParams, nil)
	if err != nil {
		return nil, fmt.Errorf("提交上传失败: %w", err)
	}
	fileInfo, err := fileInfoFromCommitResp(commitBody, parentID, fileName, size)
	if err != nil {
		return nil, err
	}

	reportProgress(size)
	return fileInfo, nil
}

// fileInfoFromCommitResp 解析 commitMultiUploadFile 响应（两种模式共用）
func fileInfoFromCommitResp(commitBody []byte, parentID, fileName string, size int64) (*model.FileInfo, error) {
	var commitResp struct {
		File struct {
			UserFileID json.RawMessage `json:"userFileId"`
			FileName   string          `json:"fileName"`
			FileSize   int64           `json:"fileSize"`
			FileMD5    string          `json:"fileMd5"`
			CreateDate string          `json:"createDate"`
		} `json:"file"`
	}
	if err := json.Unmarshal(commitBody, &commitResp); err != nil {
		return nil, fmt.Errorf("提交上传失败: 解析响应失败: %w", err)
	}
	fileID := rawJSONString(commitResp.File.UserFileID)
	if fileID == "" {
		return nil, fmt.Errorf("提交上传失败: 响应缺少 userFileId")
	}
	name := commitResp.File.FileName
	if name == "" {
		name = fileName
	}
	return &model.FileInfo{
		ID:       fileID,
		FID:      fileID,
		Name:     name,
		Size:     size,
		IsDir:    false,
		ModTime:  parse189Time(commitResp.File.CreateDate),
		ParentID: parentID,
	}, nil
}

// computeMD5s 单次顺序读取计算整文件 MD5 与各分片 MD5。
// fileMd5 = 整文件 MD5 大写 HEX；sliceMd5 = 单片时等于 fileMd5，
// 多片时 = MD5(各片MD5hex用"\n"拼接) 大写 HEX。
func computeMD5s(rs io.ReadSeeker, size, sliceSize int64) (*fileMD5Result, error) {
	fileHash := md5.New()
	slices := make([]sliceMD5, 0, (size+sliceSize-1)/sliceSize)
	sliceHexes := make([]string, 0, cap(slices))

	remaining := size
	for remaining > 0 {
		n := sliceSize
		if remaining < n {
			n = remaining
		}
		sliceHash := md5.New()
		if _, err := io.CopyN(io.MultiWriter(fileHash, sliceHash), rs, n); err != nil {
			return nil, err
		}
		sum := sliceHash.Sum(nil)
		hexUpper := strings.ToUpper(hex.EncodeToString(sum))
		slices = append(slices, sliceMD5{
			hexUpper: hexUpper,
			base64:   base64.StdEncoding.EncodeToString(sum),
		})
		sliceHexes = append(sliceHexes, hexUpper)
		remaining -= n
	}
	// 空文件：MD5 为空内容哈希，无分片
	if size == 0 {
		slices = append(slices, sliceMD5{
			hexUpper: strings.ToUpper(hex.EncodeToString(fileHash.Sum(nil))),
			base64:   base64.StdEncoding.EncodeToString(fileHash.Sum(nil)),
		})
		sliceHexes = append(sliceHexes, slices[0].hexUpper)
	}

	fileMD5 := strings.ToUpper(hex.EncodeToString(fileHash.Sum(nil)))
	sliceMD5 := fileMD5
	if len(sliceHexes) > 1 {
		h := md5.New()
		h.Write([]byte(strings.Join(sliceHexes, "\n")))
		sliceMD5 = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	}
	return &fileMD5Result{fileMD5: fileMD5, sliceMD5: sliceMD5, slices: slices}, nil
}

// putSlice PUT 单个分片：URL 追加 clientSuffix，header 用 requestHeader 原样拆解，不加签名头
func (b *pcBackend) putSlice(ctx context.Context, uploadHost, requestURL, requestHeader string, body io.Reader, size int64) error {
	full := requestURL
	if !strings.HasPrefix(full, "http://") && !strings.HasPrefix(full, "https://") {
		full = strings.TrimSuffix(uploadHost, "/") + "/" + strings.TrimPrefix(full, "/")
	}
	u, err := url.Parse(full)
	if err != nil {
		return err
	}
	q := u.Query()
	for k, v := range clientSuffix() {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	for _, kv := range strings.Split(requestHeader, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := b.c.httpClient.Do(req)
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

// progressReader 汇报读取进度（onRead 收到的是本次分片内的累计读取量）
type progressReader struct {
	r      io.Reader
	read   int64
	onRead func(n int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.onRead != nil {
		p.onRead(p.read)
	}
	return n, err
}
