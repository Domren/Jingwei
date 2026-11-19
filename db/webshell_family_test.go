package db

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

// TestWebshellFamilyID 钉住族 ID 的派生规则：同模板同密钥版本同族，任一
// 维度不同则不同族；规范化（大小写/空白）后才参与 hash；公式与 schema.sql
// 触发器的 SQL 表达式逐字对应，保证「Go 侧算出的族 ID」能查到「库里落的族」。
func TestWebshellFamilyID(t *testing.T) {
	a := WebshellFamilyID("php", "v2", "inject", 1)
	if a != WebshellFamilyID("PHP", " v2 ", "INJECT", 1) {
		t.Fatal("族 ID 应先 lower(trim()) 规范化")
	}
	if a != WebshellFamilyID("php", "v2", "inject", 1) {
		t.Fatal("同模板同版本应稳定同族")
	}
	if a == WebshellFamilyID("jsp", "v2", "inject", 1) {
		t.Fatal("模板类型不同不应同族")
	}
	if a == WebshellFamilyID("php", "v2", "php_prepend", 1) {
		t.Fatal("投放来源不同不应同族")
	}
	if a == WebshellFamilyID("php", "v2", "inject", 2) {
		t.Fatal("密钥版本不同不应同族（轮换后进入下一代族）")
	}
	if !strings.HasPrefix(a, "fam_") || len(a) != 20 {
		t.Fatalf("族 ID 形如 fam_<16 hex>，got %q (len=%d)", a, len(a))
	}

	// 与触发器 SQL 公式逐字比对，防止两侧漂移。
	canonical := "php|v2|inject|1"
	sum := md5.Sum([]byte(canonical))
	want := "fam_" + hex.EncodeToString(sum[:])[:16]
	if a != want {
		t.Fatalf("族 ID 与 schema 触发器不一致: got %q want %q", a, want)
	}
}

// TestListWebshellsByFamily 覆盖验收「同族 N 壳一次轮换、指纹+族 ID 双查」。
// 依赖真实 PG，无库时按仓库惯例跳过。
func TestListWebshellsByFamily(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	taskID := int64(0)
	mk := func(name, url string, keyVersion int) *Webshell {
		in := WebshellInput{
			Name: name, URL: url, ShellType: "php", Protocol: "v2",
			Secret: "sealed:" + name, Carrier: "jw_testcarrier",
			PayloadSHA256: strings.Repeat("a", 64), KeyVersion: keyVersion,
			Target: "http://target", Source: "inject", TaskID: &taskID,
		}
		ws, e := d.CreateWebshell(in)
		if e != nil {
			t.Fatalf("create %s: %v", name, e)
		}
		t.Cleanup(func() { _, _ = d.DeleteWebshell(ws.ID) })
		return ws
	}

	// 三只同模板同版本的壳应落在同一族；指纹与族 ID 同时可读。
	w1 := mk("f-a", "http://t/a.php", 1)
	w2 := mk("f-b", "http://t/b.php", 1)
	w3 := mk("f-c", "http://t/c.php", 1)
	family := w1.FamilyID
	if family == "" || w2.FamilyID != family || w3.FamilyID != family {
		t.Fatalf("同族三壳 family_id 不一致: %q %q %q", w1.FamilyID, w2.FamilyID, w3.FamilyID)
	}
	for _, w := range []*Webshell{w1, w2, w3} {
		if len(w.PayloadSHA256) != 64 {
			t.Fatalf("指纹应可读: id=%d sha=%q", w.ID, w.PayloadSHA256)
		}
		if w.FamilyID != family {
			t.Fatalf("族 ID 应可读: id=%d family=%q", w.ID, w.FamilyID)
		}
	}
	got, err := d.ListWebshellsByFamily(family)
	if err != nil || len(got) != 3 {
		t.Fatalf("按族查询应得 3 只，got=%d err=%v", len(got), err)
	}

	// 一次批量轮换：同一条 UPDATE 改掉全族 secret/指纹/版本，族 ID 随之
	// 进入下一代；所有壳一起迁移，不会留半族在旧版本。
	newSHA := strings.Repeat("b", 64)
	n, err := d.UpdateWebshellsSecretByFamily(family, "sealed:rotated", "jw_testcarrier", newSHA, 2)
	if err != nil || n != 3 {
		t.Fatalf("批量轮换应更新 3 行，n=%d err=%v", n, err)
	}
	nextFamily := WebshellFamilyID("php", "v2", "inject", 2)
	got, err = d.ListWebshellsByFamily(nextFamily)
	if err != nil || len(got) != 3 {
		t.Fatalf("轮换后整族应迁移到下一代，got=%d err=%v", len(got), err)
	}
	old, _ := d.ListWebshellsByFamily(family)
	if len(old) != 0 {
		t.Fatalf("旧族应为空，got=%d", len(old))
	}
	for _, w := range got {
		if w.PayloadSHA256 != newSHA || w.Secret != "sealed:rotated" {
			t.Fatalf("轮换后指纹/密钥未落库: id=%d sha=%q", w.ID, w.PayloadSHA256)
		}
	}

	// 批量撤离：一次删除整族。
	dn, err := d.DeleteWebshellsByFamily(nextFamily)
	if err != nil || dn != 3 {
		t.Fatalf("批量撤离应删 3 行，dn=%d err=%v", dn, err)
	}
}
