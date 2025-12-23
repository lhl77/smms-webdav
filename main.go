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
	SMMS_UPLOAD   = "https://smms.app/api/v2/upload"
	SMMS_DELETE   = "https://smms.app/api/v2/delete/"
	MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB
)

type Config struct {
	SmmsToken string `json:"smms_token"`
	Port      string `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type FileInfo struct {
	Hash     string    `json:"hash"`
	Path     string    `json:"path"`
	URL      string    `json:"url"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
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

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			path TEXT PRIMARY KEY,
			hash TEXT NOT NULL,
			url TEXT NOT NULL,
			size INTEGER NOT NULL,
			modified TEXT NOT NULL
		)
	`)
	return err
}

func saveFile(info *FileInfo) error {
	modifiedStr := info.Modified.Format(time.RFC3339)
	_, err := db.Exec(
		"INSERT OR REPLACE INTO files (path, hash, url, size, modified) VALUES (?, ?, ?, ?, ?)",
		info.Path, info.Hash, info.URL, info.Size, modifiedStr,
	)
	return err
}

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

func deleteFile(path string) error {
	_, err := db.Exec("DELETE FROM files WHERE path = ?", path)
	return err
}

func listAllFiles() ([]FileInfo, error) {
	rows, err := db.Query("SELECT path, hash, url, size, modified FROM files ORDER BY path")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []FileInfo
	for rows.Next() {
		var f FileInfo
		var modifiedStr string
		if err := rows.Scan(&f.Path, &f.Hash, &f.URL, &f.Size, &modifiedStr); err != nil {
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
		Success bool      `json:"success"`
		Data    SmmsImage `json:"data"`
		Message string    `json:"message"`
	}
	json.Unmarshal(resp.Body(), &result)

	if !result.Success {
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
	info.Path = name

	if err := saveFile(info); err != nil {
		http.Error(w, "Save to DB failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] Uploaded: %s (hash: %s)\n", name, info.Hash)
	w.WriteHeader(http.StatusCreated)
}

func handleDELETE(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	info, err := getFile(name)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if err := deleteFile(name); err != nil {
		http.Error(w, "DB delete failed", http.StatusInternalServerError)
		return
	}

	if err := deleteFromSmms(info.Hash); err != nil {
		fmt.Printf("[-] Delete warning: %v\n", err)
	}
	fmt.Printf("[-] Deleted: %s\n", name)
	w.WriteHeader(http.StatusNoContent)
}

func handleGET(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		// Treat root GET as PROPFIND for compatibility
		handlePROPFIND(w, r, "")
		return
	}

	info, err := getFile(name)
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

		// 构造响应
		responses := []PropfindResponseItem{
			{
				Href: "/",
				Props: Propstat{
					Prop: Prop{
						Resourcetype: &struct {
							Collection *struct{} `xml:"D:collection,omitempty"`
						}{
							Collection: &struct{}{}, // 非 nil 表示是目录
						},
					},
					Status: "HTTP/1.1 200 OK",
				},
			},
		}

		for _, info := range files {
			href := "/" + url.PathEscape(info.Path) // URL 编码路径
			prop := Prop{
				Resourcetype: &struct {
					Collection *struct{} `xml:"D:collection,omitempty"`
				}{}, // Collection 为 nil → 输出 <D:resourcetype/>
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

	// 单个文件 PROPFIND
	info, err := getFile(name)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	href := "/" + url.PathEscape(info.Path)
	prop := Prop{
		Resourcetype: &struct {
			Collection *struct{} `xml:"D:collection,omitempty"`
		}{}, // 文件无 collection
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

	http.HandleFunc("/", authHandler)
	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		fmt.Printf("💥 Server failed: %v\n", err)
	}
}
