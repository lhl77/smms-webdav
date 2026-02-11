package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	_ "modernc.org/sqlite"
)

const (
	DB_FILE       = "smms.db"
	CONFIG_FILE   = "config.json"
	SMMS_UPLOAD   = "https://s.ee/api/v1/file/upload"
	SMMS_DELETE   = "https://s.ee/api/v1/file/delete/"
	MAX_FILE_SIZE = 20 * 1024 * 1024 // 20MB
)

type Config struct {
	SmmsToken string `json:"smms_token"`
	Port      string `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type FileInfo struct {
	Hash         string    `json:"hash"`
	Path         string    `json:"path"`          // CDN path (主键)
	OriginalPath string    `json:"original_path"` // 新增字段
	URL          string    `json:"url"`
	Size         int64     `json:"size"`
	Modified     time.Time `json:"modified"`
}

var (
	db     *sql.DB
	config Config
	client *resty.Client
)

// ------------------ Config ------------------
func loadConfig() error {
	if _, err := os.Stat(CONFIG_FILE); os.IsNotExist(err) {
		defaultConf := Config{
			SmmsToken: "",
			Port:      "8080",
			Username:  "",
			Password:  "",
		}
		data, _ := json.MarshalIndent(defaultConf, "", "  ")
		os.WriteFile(CONFIG_FILE, data, 0600)
		fmt.Printf("🔧 %s not found. Created template. Please edit it and restart.\n", CONFIG_FILE)
		os.Exit(1)
	}

	data, err := os.ReadFile(CONFIG_FILE)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if config.Port == "" {
		config.Port = "8080"
	}

	return nil
}

// ------------------ SQLite DB ------------------
func initDB() error {
	var err error
	db, err = sql.Open("sqlite", DB_FILE+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=30000")
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}

	// ✅ 使用 IF NOT EXISTS 避免重复创建
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			path TEXT PRIMARY KEY,
			original_path TEXT,
			hash TEXT NOT NULL,
			url TEXT NOT NULL,
			size INTEGER NOT NULL,
			modified TEXT NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	return nil
}

func saveFile(info *FileInfo) error {
	modifiedStr := info.Modified.Format(time.RFC3339)
	_, err := db.Exec(
		"INSERT OR REPLACE INTO files (path, original_path, hash, url, size, modified) VALUES (?, ?, ?, ?, ?, ?)",
		info.Path, info.OriginalPath, info.Hash, info.URL, info.Size, modifiedStr,
	)
	return err
}

// ------------------ DB Helpers ------------------
// 原有的 getFile 保持不变（按 CDN path 查询）
func getFile(path string) (*FileInfo, error) {
	row := db.QueryRow("SELECT hash, url, size, modified FROM files WHERE path = ?", path)
	var info FileInfo
	var modifiedStr string
	err := row.Scan(&info.Hash, &info.URL, &info.Size, &modifiedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	info.Path = path
	info.Modified, _ = time.Parse(time.RFC3339, modifiedStr)
	return &info, nil
}

// ✅ 按 original_path 查询
func getFileByOriginalPath(originalPath string) (*FileInfo, error) {
	row := db.QueryRow("SELECT path, original_path, hash, url, size, modified FROM files WHERE original_path = ?", originalPath)
	var info FileInfo
	var modifiedStr string
	err := row.Scan(&info.Path, &info.OriginalPath, &info.Hash, &info.URL, &info.Size, &modifiedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	info.Modified, _ = time.Parse(time.RFC3339, modifiedStr)
	return &info, nil
}

func deleteFile(path string) error {
	_, err := db.Exec("DELETE FROM files WHERE path = ?", path)
	return err
}

func listAllFiles() ([]FileInfo, error) {
	rows, err := db.Query("SELECT path, original_path, hash, url, size, modified FROM files ORDER BY original_path")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []FileInfo
	for rows.Next() {
		var f FileInfo
		var modifiedStr string
		if err := rows.Scan(&f.Path, &f.OriginalPath, &f.Hash, &f.URL, &f.Size, &modifiedStr); err != nil {
			return nil, err
		}
		f.Modified, _ = time.Parse(time.RFC3339, modifiedStr)
		files = append(files, f)
	}
	return files, nil
}

// ------------------ sm.ms API ------------------
type SmmsImage struct {
	Filename  string `json:"filename"`
	Size      int    `json:"size"`
	Path      string `json:"path"`
	Hash      string `json:"hash"`
	URL       string `json:"url"`
	CreatedAt int    `json:"created_at"`
}

func uploadToSmms(filename string, content []byte) (*FileInfo, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("smfile", filename)
	part.Write(content)
	writer.Close()

	req := client.R().
		SetHeader("Content-Type", writer.FormDataContentType()).
		SetBody(body.Bytes())

	if config.SmmsToken != "" {
		req.SetHeader("Authorization", config.SmmsToken)
	}

	resp, err := req.Post(SMMS_UPLOAD)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data    SmmsImage `json:"data"`
		Message string    `json:"message"`
		Code    int       `json:"code"`
	}
	json.Unmarshal(resp.Body(), &result)

	if result.Code != 200 {
		if strings.Contains(result.Message, "Image exists") {
			return nil, fmt.Errorf("file already exists on sm.ms (duplicate content)")
		}
		return nil, fmt.Errorf("sm.ms: %s", result.Message)
	}

	mtime := time.Now()
	if result.Data.CreatedAt > 0 {
		mtime = time.Unix(int64(result.Data.CreatedAt), 0)
	}

	return &FileInfo{
		Hash:     result.Data.Hash,
		URL:      result.Data.URL,
		Size:     int64(result.Data.Size),
		Modified: mtime,
	}, nil
}

func deleteFromSmms(hash string) error {
	url := SMMS_DELETE + hash
	req := client.R()
	if config.SmmsToken != "" {
		req.SetHeader("Authorization", config.SmmsToken)
	}
	resp, err := req.Get(url)
	if err != nil {
		return err
	}

	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	json.Unmarshal(resp.Body(), &result)

	if !result.Success {
		return fmt.Errorf("delete failed: %s", result.Message)
	}
	return nil
}

// ------------------ WebDAV XML Types (修复命名空间) ------------------
type Prop struct {
	Resourcetype *struct {
		Collection *struct{} `xml:"D:collection,omitempty"` // ✅ 关键：带 D: 前缀
	} `xml:"D:resourcetype,omitempty"`
	Getcontentlength *int64 `xml:"D:getcontentlength,omitempty"`
	Getlastmodified  string `xml:"D:getlastmodified,omitempty"`
}

type Propstat struct {
	Prop   Prop   `xml:"D:prop"`
	Status string `xml:"D:status"`
}

type PropfindResponseItem struct {
	Href  string   `xml:"D:href"`
	Props Propstat `xml:"D:propstat"`
}

type PropfindResponse struct {
	XMLName   xml.Name               `xml:"D:multistatus"`
	XmlnsD    string                 `xml:"xmlns:D,attr"` // 声明命名空间
	Responses []PropfindResponseItem `xml:"D:response"`
}

// ------------------ WebDAV Handler ------------------
func normalizePath(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" || strings.Contains(p, "..") {
		return ""
	}
	return p
}

func webdavHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, PROPFIND, OPTIONS")

	path := normalizePath(r.URL.Path)

	switch r.Method {
	case "PUT":
		handlePUT(w, r, path)
	case "DELETE":
		handleDELETE(w, r, path)
	case "GET", "HEAD":
		handleGET(w, r, path)
	case "PROPFIND":
		handlePROPFIND(w, r, path)
	case "OPTIONS":
		handleOPTIONS(w, r, path)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, PROPFIND, OPTIONS")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleOPTIONS(w http.ResponseWriter, r *http.Request, path string) {
	w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, PROPFIND, OPTIONS")
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

func handlePUT(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if r.ContentLength > 0 && r.ContentLength > MAX_FILE_SIZE {
		http.Error(w, "File too large (max 10MB)", http.StatusRequestEntityTooLarge)
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(content) > MAX_FILE_SIZE {
		http.Error(w, "File too large (max 10MB)", http.StatusRequestEntityTooLarge)
		return
	}

	info, err := uploadToSmms(filepath.Base(name), content)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			http.Error(w, "File already exists on sm.ms (duplicate content)", http.StatusConflict)
			return
		}
		http.Error(w, "Upload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	info.OriginalPath = name

	// 🔑 关键修改：从 info.URL 提取 clean path 作为新的存储 path
	var finalPath string
	if u, err := url.Parse(info.URL); err == nil {
		finalPath = strings.TrimPrefix(u.Path, "/")
	} else {
		// 如果解析失败，回退到原始 name
		finalPath = strings.TrimPrefix(name, "/")
	}

	// 确保不为空
	if finalPath == "" {
		finalPath = filepath.Base(name)
	}

	info.Path = finalPath // 👈 使用 CDN 路径作为主键

	if err := saveFile(info); err != nil {
		http.Error(w, "Save to DB failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] Uploaded: original=%s → stored as=%s (hash: %s)\n", name, finalPath, info.Hash)
	w.WriteHeader(http.StatusCreated)
}

func handleDELETE(w http.ResponseWriter, r *http.Request, inputPath string) {
	if inputPath == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	var info *FileInfo
	var err error
	var deleteBy string // "path" or "original_path"

	// 1️⃣ 先尝试按 CDN path (files.path) 查找
	info, err = getFile(inputPath)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if info != nil {
		deleteBy = "path"
	} else {
		// 2️⃣ 没找到？再按 original_path 查找
		info, err = getFileByOriginalPath(inputPath)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if info != nil {
			deleteBy = "original_path"
		}
	}

	// ❌ 都没找到
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// 🗑️ 执行删除：根据匹配方式决定 WHERE 条件
	var delErr error
	if deleteBy == "path" {
		_, delErr = db.Exec("DELETE FROM files WHERE path = ?", inputPath)
	} else {
		_, delErr = db.Exec("DELETE FROM files WHERE original_path = ?", inputPath)
	}

	if delErr != nil {
		http.Error(w, "DB delete failed", http.StatusInternalServerError)
		return
	}

	// 🌐 调用 sm.ms 删除（用 hash 即可，与路径无关）
	if err := deleteFromSmms(info.Hash); err != nil {
		fmt.Printf("[-] Delete warning (sm.ms): %v\n", err)
	}

	fmt.Printf("[-] Deleted via %s: %s (hash: %s, original: %s)\n",
		deleteBy, inputPath, info.Hash, info.OriginalPath)

	w.WriteHeader(http.StatusNoContent)
}

func handleGET(w http.ResponseWriter, r *http.Request, originalPath string) {
	if originalPath == "" {
		handlePROPFIND(w, r, "")
		return
	}

	info, err := getFileByOriginalPath(originalPath)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, info.URL, http.StatusFound)
}

func handlePROPFIND(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		files, err := listAllFiles()
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		responses := []PropfindResponseItem{
			{
				Href: "/",
				Props: Propstat{
					Prop: Prop{
						Resourcetype: &struct {
							Collection *struct{} `xml:"D:collection,omitempty"`
						}{
							Collection: &struct{}{},
						},
					},
					Status: "HTTP/1.1 200 OK",
				},
			},
		}

		for _, info := range files {
			// ✅ 使用 original_path 构造 href（如果为空，回退到 path）
			displayPath := info.OriginalPath
			if displayPath == "" {
				displayPath = info.Path
			}
			href := "/" + url.PathEscape(displayPath)
			prop := Prop{
				Getcontentlength: &info.Size,
				Getlastmodified:  info.Modified.Format(time.RFC1123Z),
			}
			responses = append(responses, PropfindResponseItem{
				Href: href,
				Props: Propstat{
					Prop:   prop,
					Status: "HTTP/1.1 200 OK",
				},
			})
		}

		w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
		w.Header().Set("DAV", "1, 2")
		w.WriteHeader(http.StatusMultiStatus)

		resp := PropfindResponse{
			XmlnsD:    "DAV:",
			Responses: responses,
		}
		xml.NewEncoder(w).Encode(resp)
		return
	}

	// 单个文件：按 original_path 查
	info, err := getFileByOriginalPath(name)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	displayPath := info.OriginalPath
	if displayPath == "" {
		displayPath = info.Path
	}
	href := "/" + url.PathEscape(displayPath)
	prop := Prop{
		Getcontentlength: &info.Size,
		Getlastmodified:  info.Modified.Format(time.RFC1123Z),
	}
	response := PropfindResponseItem{
		Href: href,
		Props: Propstat{
			Prop:   prop,
			Status: "HTTP/1.1 200 OK",
		},
	}

	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.Header().Set("DAV", "1, 2")
	w.WriteHeader(http.StatusMultiStatus)

	resp := PropfindResponse{
		XmlnsD:    "DAV:",
		Responses: []PropfindResponseItem{response},
	}
	xml.NewEncoder(w).Encode(resp)
}

// ------------------ Main ------------------
func main() {
	if err := loadConfig(); err != nil {
		fmt.Printf("❌ Config error: %v\n", err)
		os.Exit(1)
	}

	client = resty.New().SetTimeout(60 * time.Second)

	if err := initDB(); err != nil {
		fmt.Printf("❌ DB init failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 sm.ms WebDAV server running on :%s\n", config.Port)
	fmt.Printf("📁 DB: %s\n", DB_FILE)
	fmt.Printf("⚙️  Config: %s\n", CONFIG_FILE)
	if config.SmmsToken != "" {
		fmt.Println("🔑 Using sm.ms token from config")
	} else {
		fmt.Println("🔓 Running in anonymous mode (no token)")
	}

	authHandler := func(w http.ResponseWriter, r *http.Request) {
		// 允许 GET、HEAD、OPTIONS 无需认证（图片可公开访问）
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if config.Username != "" {
				user, pass, ok := r.BasicAuth()
				if !ok || user != config.Username || pass != config.Password {
					w.Header().Set("WWW-Authenticate", `Basic realm="sm.ms WebDAV"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}
		webdavHandler(w, r)
	}

	http.HandleFunc("/api/get-url", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		originalPath := normalizePath(r.URL.Query().Get("path"))
		if originalPath == "" {
			http.Error(w, "Missing or invalid path", http.StatusBadRequest)
			return
		}

		// 先按 original_path 查
		info, err := getFileByOriginalPath(originalPath)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 再按 CDN path 查（兼容）
		if info == nil {
			info, err = getFile(originalPath)
			if err != nil {
				http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if info == nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		// ✅ 返回 JSON，但 "url" 字段是 CDN 路径（info.Path）
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{
			"url": info.Path, // 👈 关键：用 Path 而不是 URL
		})
	})

	http.HandleFunc("/", authHandler)
	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		fmt.Printf("💥 Server failed: %v\n", err)
	}

}
