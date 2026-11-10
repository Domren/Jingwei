package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/jingwei/scanner"
)

// 实机回归（2026-11-10）：贴进来的目标清单是一行一条，seed 与预扫却只取第一条，
// 12 条授权目标开局只有 1 条进预扫。这里钉住「清单里每条都要被解析出来」。
func TestParseTargetListCoversEveryTarget(t *testing.T) {
	text := "10.33.222.13\n" +
		"http://10.33.237.140:1111/#/\n" +
		"http://172.18.154.31:90/adminapi/pub/userNotLogin.html\n" +
		"http://10.33.237.140:1111/#/\n" + // 重复行
		"顺手写的备注 example.com:8443 和 10.0.252.23\n"
	want := []string{
		"http://10.33.222.13",
		"http://10.33.237.140:1111",
		"http://172.18.154.31:90",
		"https://example.com:8443",
		"http://10.0.252.23",
	}
	got := parseTargetList(text)
	if len(got) != len(want) {
		t.Fatalf("解析到 %d 条，期望 %d 条: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].rawURL != w {
			t.Errorf("第 %d 条 = %q，期望 %q", i+1, got[i].rawURL, w)
		}
	}
}

func TestParseTargetListCapsAndDedupes(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= maxSeedTargets+8; i++ {
		fmt.Fprintf(&b, "http://10.%d.%d.7:8080\r\n", i%250, i%200)
	}
	got := parseTargetList(b.String())
	if len(got) != maxSeedTargets {
		t.Fatalf("上限未生效: 解析到 %d 条，期望 %d", len(got), maxSeedTargets)
	}
	again := parseTargetList("http://a.example:80/x http://a.example:80/y")
	if len(again) != 1 || again[0].rawURL != "http://a.example" {
		t.Errorf("同一 host:port 的不同路径应归并为一条，实际 %+v", again)
	}
}

func TestGroupTargetsByPortSpec(t *testing.T) {
	seeds := parseTargetList("http://10.0.0.1/ https://10.0.0.2/ http://10.0.0.3:9011/ http://10.0.0.4:9012/")
	groups := groupTargetsByPortSpec(seeds)
	if len(groups) != 3 {
		t.Fatalf("分组数 = %d，期望 3（web 一组 + 两个独立端口）: %+v", len(groups), groups)
	}
	if groups[0].portSpec != "web" || len(groups[0].urls) != 2 {
		t.Errorf("web 组 = %+v，期望两条 80/443 目标", groups[0])
	}
	if groups[1].portSpec != "9011" || groups[2].portSpec != "9012" {
		t.Errorf("奇数端口应各自成组，实际 %+v", groups)
	}
}

func TestMergeDiscoverResultsDedupes(t *testing.T) {
	dst := &scanner.DiscoverResult{
		Resolved: &scanner.Resolved{IPs: []string{"10.0.0.7"}, DomainsByIP: map[string][]string{"10.0.0.7": {"a.example"}}},
		Ports:    []scanner.PortFinding{{IP: "10.0.0.7", Port: 80, Service: "http"}},
		Services: []scanner.WebService{{URL: "http://10.0.0.7:80"}},
		PortList: []int{80},
	}
	src := &scanner.DiscoverResult{
		Resolved: &scanner.Resolved{IPs: []string{"10.0.0.7", "10.0.0.8"}, DomainsByIP: map[string][]string{"10.0.0.7": {"a.example"}}},
		Ports: []scanner.PortFinding{
			{IP: "10.0.0.7", Port: 80, Service: "http"}, // 与 dst 重复
			{IP: "10.0.0.7", Port: 9011, Service: "http"},
		},
		Services: []scanner.WebService{{URL: "http://10.0.0.7:80"}, {URL: "http://10.0.0.7:9011"}},
		PortList: []int{80, 9011},
	}
	mergeDiscoverResults(dst, src)
	if len(dst.Resolved.IPs) != 2 {
		t.Errorf("IP 去重失败: %v", dst.Resolved.IPs)
	}
	if len(dst.Ports) != 2 {
		t.Errorf("端口发现去重失败: %+v", dst.Ports)
	}
	if len(dst.Services) != 2 {
		t.Errorf("服务去重失败: %+v", dst.Services)
	}
	if len(dst.PortList) != 2 {
		t.Errorf("端口清单去重失败: %v", dst.PortList)
	}
	if got := len(dst.Resolved.DomainsByIP["10.0.0.7"]); got != 1 {
		t.Errorf("同 IP 的域名重复合并后 = %d，期望 1", got)
	}
}

// seed 阶段就要把清单里每条都登记成根资产，否则其余目标在资产图上根本不存在，
// planner 的 graph_overview 开局也看不见它们。
func TestSeedRegistersEveryTarget(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("多目标 seed", "多目标 seed", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{DeleteAssets: true}) })

	hostA := fmt.Sprintf("seed-a-%s.example.test", task.ID)
	hostB := fmt.Sprintf("seed-b-%s.example.test", task.ID)
	s := &Server{m: m}
	s.seed(task, "https://"+hostA+"\nhttp://"+hostB+":8080/")

	assets, err := m.Assets().QueryByTask(mustTaskID(t, task.ID), "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range assets {
		if a.Domain != "" {
			seen[a.Domain] = true
		}
		if strings.Contains(a.URL, hostA) {
			seen[hostA] = true
		}
		if strings.Contains(a.URL, hostB) {
			seen[hostB] = true
		}
	}
	for _, h := range []string{hostA, hostB} {
		if !seen[h] {
			t.Errorf("目标 %s 没有被 seed 成任务资产: %+v", h, assets)
		}
	}
}
