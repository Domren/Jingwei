package db

import (
	"strconv"
	"strings"
	"testing"
)

// 2026-11-10 实机回归：planner 自然写出 `status_code >= 0`（比较式两边带空格），旧解析器
// 只认 `status_code>=0`，带空格时被切成三个裸词、报「意外的内容 'BARE'」，模型看不懂该改哪里，
// 白烧一次工具轮。这里把两种写法都钉成可执行条件，并钉住错误信息里带上具体词。
func TestAssetDSLAllowsSpacesAroundOperator(t *testing.T) {
	cases := []struct {
		dsl       string
		wantSQL   string
		wantArg0  string
		wantArgsN int
	}{
		{"status_code >= 0", "status_code >= $1", "0", 1},
		{"status_code>=0", "status_code >= $1", "0", 1},
		{"status_code >= 200 and port != 80", "(status_code >= $1) AND (port != $2)", "200", 2},
		{"port > 8080", "port > $1", "8080", 1},
		{"status == 404", "status_code = $1", "404", 1},
		{"url = \"http://a.example/x\" and technology = nginx", "", "", 2},
	}
	for _, c := range cases {
		node, err := ParseDSL(c.dsl)
		if err != nil {
			t.Errorf("ParseDSL(%q) 报错: %v", c.dsl, err)
			continue
		}
		sql, args, err := buildDSLWhere(node)
		if err != nil {
			t.Errorf("buildDSLWhere(%q) 报错: %v", c.dsl, err)
			continue
		}
		if c.wantSQL != "" && sql != c.wantSQL {
			t.Errorf("ParseDSL(%q) 生成 = %q，期望 %q", c.dsl, sql, c.wantSQL)
		}
		if len(args) != c.wantArgsN {
			t.Errorf("ParseDSL(%q) 参数数 = %d (%v)，期望 %d", c.dsl, len(args), args, c.wantArgsN)
			continue
		}
		if c.wantArg0 != "" && strconv.FormatInt(toInt(t, args[0]), 10) != c.wantArg0 {
			t.Errorf("ParseDSL(%q) 首参 = %v，期望 %s", c.dsl, args[0], c.wantArg0)
		}
		if err := ValidateDSL(c.dsl); err != nil {
			t.Errorf("ValidateDSL(%q) 报错: %v", c.dsl, err)
		}
	}
}

func toInt(t *testing.T, v any) int64 {
	t.Helper()
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	}
	t.Fatalf("参数不是整数: %#v", v)
	return 0
}

// 缺值与裸词连写仍然要报错，但报错得说清楚是哪一段不对。
func TestAssetDSLErrorNamesOffendingWord(t *testing.T) {
	cases := []struct {
		dsl      string
		wantText string
	}{
		{"foo bar", `"bar"`},       // 两个裸词之间缺 AND/OR
		{"status_code >=", `">="`}, // 比较式没有值：退化成裸词后仍要报错，并点出那一段
	}
	for _, c := range cases {
		if _, err := ParseDSL(c.dsl); err == nil {
			t.Errorf("ParseDSL(%q) 应当报错却没有", c.dsl)
			continue
		} else if !strings.Contains(err.Error(), c.wantText) {
			t.Errorf("ParseDSL(%q) 错误信息没有指出具体位置: %v", c.dsl, err)
		}
	}
}
