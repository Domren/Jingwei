package db

import (
	"testing"
	"time"
)

// TestAuthorizationRoundTrip 钉住授权清单的存储层本身。
//
// 为什么单独写：F4 原先只有「匹配语义」的单测（纯函数），一次都没真的往库里写过，
// 于是两个只有走数据库才会暴露的错误一路活到了浏览器验证阶段——LIMIT 的占位符没传参、
// 数组列读不回来。纯函数测得再多，也不等于这个功能能跑。
func TestAuthorizationRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	const prefix = "authz-roundtrip-"
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM authorizations WHERE name LIKE $1`, prefix+"%")
	})

	now := time.Now().UTC()
	starts := now.Add(-time.Hour)
	ends := now.Add(7 * 24 * time.Hour)

	created, err := d.CreateAuthorization(AuthorizationInput{
		Name:       prefix + "主授权",
		Targets:    []string{"10.0.0.0/8", "CORP.Example.com", " 10.0.0.0/8 ", ".internal.test"},
		Exclusions: []string{"10.9.9.9"},
		StartsAt:   &starts,
		EndsAt:     &ends,
		Enabled:    true,
		Note:       "round trip",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 去重、去空格、小写都应在同一趟里做完，guard 匹配时不再各自解释一遍。
	want := []string{"10.0.0.0/8", "corp.example.com", ".internal.test"}
	if len(created.Targets) != len(want) {
		t.Fatalf("targets = %v，期望 %v", created.Targets, want)
	}
	for i := range want {
		if created.Targets[i] != want[i] {
			t.Fatalf("targets[%d] = %q，期望 %q", i, created.Targets[i], want[i])
		}
	}

	// 读回来必须和写进去一致（数组列曾经的失败点就在这里）。
	list, err := d.ListAuthorizations(50)
	if err != nil {
		t.Fatal(err)
	}
	var got *Authorization
	for _, a := range list {
		if a.ID == created.ID {
			got = a
		}
	}
	if got == nil {
		t.Fatalf("列表里没有刚建的授权：%+v", list)
	}
	if len(got.Exclusions) != 1 || got.Exclusions[0] != "10.9.9.9" {
		t.Fatalf("exclusions = %v", got.Exclusions)
	}
	if got.StartsAt == nil || got.EndsAt == nil {
		t.Fatalf("时间窗没读回来: %+v", got)
	}
	if !got.Enabled || got.Note != "round trip" {
		t.Fatalf("启用位/备注不对: %+v", got)
	}

	active, err := d.ListActiveAuthorizations()
	if err != nil {
		t.Fatal(err)
	}
	if !containsAuthzID(active, created.ID) {
		t.Fatalf("在时间窗内的授权没进有效清单: %+v", active)
	}

	// LIMIT 真的生效（占位符漏传参数时，这条会直接报错而不是悄悄全量返回）。
	for i := 0; i < 3; i++ {
		if _, err := d.CreateAuthorization(AuthorizationInput{
			Name: prefix + "多条", Targets: []string{"203.0.113.0/24"}, Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	limited, err := d.ListAuthorizations(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 {
		t.Fatalf("limit=2 拿到 %d 条", len(limited))
	}

	// 过期与停用都不算「有效授权」——授权清单只放行当下还成立的条目。
	expired := now.Add(-48 * time.Hour)
	if _, err := d.CreateAuthorization(AuthorizationInput{
		Name: prefix + "已过期", Targets: []string{"198.51.100.0/24"}, EndsAt: &expired, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	offStart := now.Add(24 * time.Hour)
	offEnd := now.Add(48 * time.Hour)
	if _, err := d.CreateAuthorization(AuthorizationInput{
		Name: prefix + "还没开始", Targets: []string{"198.51.100.0/24"}, StartsAt: &offStart, EndsAt: &offEnd, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateAuthorization(AuthorizationInput{
		Name: prefix + "停用", Targets: []string{"198.51.100.0/24"}, Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	active, err = d.ListActiveAuthorizations()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range active {
		if a.Name == prefix+"已过期" || a.Name == prefix+"还没开始" || a.Name == prefix+"停用" {
			t.Fatalf("%q 不该在有效授权里", a.Name)
		}
	}

	// 校验：没有目标、结束早于开始，都不该落库。
	if _, err := d.CreateAuthorization(AuthorizationInput{Name: prefix + "空目标"}); err == nil {
		t.Fatal("没有目标范围的授权应被拒")
	}
	if _, err := d.CreateAuthorization(AuthorizationInput{
		Name: prefix + "时间反了", Targets: []string{"10.0.0.1"}, StartsAt: &ends, EndsAt: &starts,
	}); err == nil {
		t.Fatal("结束早于开始的授权应被拒")
	}

	ok, err := d.DeleteAuthorization(created.ID)
	if err != nil || !ok {
		t.Fatalf("删除: ok=%v err=%v", ok, err)
	}
	if ok, err = d.DeleteAuthorization(created.ID); err != nil || ok {
		t.Fatalf("重复删除应报没删到: ok=%v err=%v", ok, err)
	}
}

func containsAuthzID(list []*Authorization, id int64) bool {
	for _, a := range list {
		if a.ID == id {
			return true
		}
	}
	return false
}
