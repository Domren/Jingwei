package server

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to the work dir root (traversal via ".." is neutralised). All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

// wsRelative first validates the API path and returns a workspace-relative
// name. os.Root then keeps each filesystem operation beneath the pinned root.
func (s *Server) wsRelative(rel string) (string, bool) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return ".", true
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return "", false
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return clean, true
}

// wsRoot pins the directory for the duration of a request. Root operations do
// not escape it even if a directory is replaced with a symlink concurrently.
func (s *Server) wsRoot() (*os.Root, error) {
	return os.OpenRoot(s.m.dir)
}

// wsResolve retains the absolute-path contract for existing callers, while
// rejecting symlinks already present at check time. Handlers must use wsRoot
// for actual I/O, because this check alone cannot prevent a replacement race.
func (s *Server) wsResolve(rel string) (string, bool) {
	clean, ok := s.wsRelative(rel)
	if !ok {
		return "", false
	}
	base := filepath.Clean(s.m.dir)
	abs := filepath.Join(base, clean)
	root, err := s.wsRoot()
	if err != nil {
		return "", false
	}
	defer root.Close()
	current := ""
	for _, part := range strings.Split(clean, string(os.PathSeparator)) {
		if part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
	}
	return abs, true
}

// wsRel renders an absolute path back as a workspace-relative path (forward slashes).
func (s *Server) wsRel(abs string) string {
	base := filepath.Clean(s.m.dir)
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	root, err := s.wsRoot()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	fi, err := root.Stat(s.wsRel(abs))
	if err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, "不是目录")
		return
	}
	dir, err := root.Open(s.wsRel(abs))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer dir.Close()
	ents, err := dir.ReadDir(-1)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  s.wsRel(filepath.Join(abs, e.Name())),
			Dir:   e.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// 目录在前，各自按名称排序。
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	root, err := s.wsRoot()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	file, err := root.Open(s.wsRel(abs))
	if err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if fi.IsDir() {
		writeErr(w, 400, "是目录，不能作为文件读取")
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceRead+1))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "非法路径")
		return
	}
	root, err := s.wsRoot()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	rel := s.wsRel(abs)
	if fi, err := root.Stat(rel); err == nil && fi.IsDir() {
		writeErr(w, 400, "目标是目录")
		return
	}
	if err := root.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	file, err := root.OpenFile(rel, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	_, copyErr := io.WriteString(file, req.Content)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		writeErr(w, 500, "写入文件失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "非法路径")
		return
	}
	root, err := s.wsRoot()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	if err := root.MkdirAll(s.wsRel(abs), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "不能删除工作区根目录")
		return
	}
	root, err := s.wsRoot()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	rel := s.wsRel(abs)
	if _, err := root.Lstat(rel); err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	if err := root.RemoveAll(rel); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	root, err := s.wsRoot()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	file, err := root.Open(s.wsRel(abs))
	if err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || fi.IsDir() {
		writeErr(w, 404, "文件不存在")
		return
	}
	name := filepath.Base(abs)
	// RFC 5987 filename* keeps non-ASCII names intact; plain filename is the fallback.
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
	http.ServeContent(w, r, name, fi.ModTime(), file)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	dirAbs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	root, err := s.wsRoot()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer root.Close()
	dir, err := root.Open(s.wsRel(dirAbs))
	if err != nil {
		writeErr(w, 400, "目标目录不存在")
		return
	}
	fi, err := dir.Stat()
	dir.Close()
	if err != nil || !fi.IsDir() {
		writeErr(w, 400, "目标目录不存在")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "解析上传失败或超出大小限制："+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "缺少上传文件(表单字段 file)")
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		destAbs, okd := s.wsResolve(filepath.Join(s.wsRel(dirAbs), name))
		if !okd {
			continue
		}
		if err := saveUploadRoot(root, hdr, s.wsRel(destAbs)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

func saveUploadRoot(root *os.Root, hdr *multipart.FileHeader, rel string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := root.OpenFile(rel, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func saveUpload(hdr *multipart.FileHeader, dest string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}

// saveWorkspaceExport persists an exported report under reports/<date>/ inside
// the shared workspace and returns its workspace-relative path. A failed save
// never blocks the download itself; callers log and continue.
func (s *Server) saveWorkspaceExport(name string, write func(*os.File) error) (string, error) {
	date := time.Now().Format("2006-01-02")
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	// O_EXCL 保证并发/同毫秒导出不会互相覆盖;冲突时追加 -1、-2…
	for attempt := 0; attempt < 1000; attempt++ {
		candidate := name
		if attempt > 0 {
			candidate = fmt.Sprintf("%s-%d%s", stem, attempt, ext)
		}
		rel := filepath.ToSlash(filepath.Join("reports", date, candidate))
		abs, ok := s.wsResolve(rel)
		if !ok {
			return "", fmt.Errorf("非法导出路径 %q", rel)
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return "", err
		}
		f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		writeErr := write(f)
		closeErr := f.Close()
		if writeErr != nil {
			_ = os.Remove(abs)
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return rel, nil
	}
	return "", fmt.Errorf("无法为导出文件分配唯一名称 %q", name)
}

func (s *Server) saveWorkspaceExportBytes(name string, data []byte) (string, error) {
	return s.saveWorkspaceExport(name, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}

func (s *Server) saveWorkspaceExportFile(name, src string) (string, error) {
	return s.saveWorkspaceExport(name, func(f *os.File) error {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(f, in)
		return err
	})
}
