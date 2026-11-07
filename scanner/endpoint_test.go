package scanner

import (
	"strings"
	"testing"
)

// 终端防护识别与补丁基线（F5）的用例。
//
// 两条最容易出错的方向都有专门断言：
//   - 误报：一个不像安全产品的进程名被说成「装了杀软」，后续动作会围着不存在的防护做决策；
//   - 误空：命令没跑成/输出被截断，被写成「没有终端防护」「不缺补丁」。
// 输入全部用真实命令的输出形态（tasklist /fo csv、sc query、ps 定宽列、systeminfo、
// wmic qfe、Get-HotFix），不自己发明格式。

func matchedProducts(rep EndpointReport) []string {
	out := make([]string, 0, len(rep.Matches))
	for _, m := range rep.Matches {
		out = append(out, m.Product)
	}
	return out
}

func hasProduct(rep EndpointReport, want string) bool {
	for _, p := range matchedProducts(rep) {
		if p == want {
			return true
		}
	}
	return false
}

func TestIdentifyEndpointSecurityWindowsTasklist(t *testing.T) {
	out := strings.Join([]string{
		`"Image Name","PID","Session Name","Session#","Mem Usage"`,
		`"MsMpEng.exe","4120","Services","0","118,124 K"`,
		`"HipsTray.exe","6632","Console","1","12,340 K"`,
		`"chrome.exe","9012","Console","1","210,000 K"`,
		`"svchost.exe","1024","Services","0","9,000 K"`,
	}, "\n")
	rep := IdentifyEndpointSecurity("windows", out)
	if rep.Empty {
		t.Fatal("有进程行却被判成空输入")
	}
	if !hasProduct(rep, "Microsoft Defender 防病毒") {
		t.Fatalf("没认出 Defender：%+v", matchedProducts(rep))
	}
	if !hasProduct(rep, "火绒安全软件") {
		t.Fatalf("没认出火绒：%+v", matchedProducts(rep))
	}
	for _, m := range rep.Matches {
		if strings.Contains(strings.ToLower(m.Line), "chrome") {
			t.Fatalf("chrome 被当成安全产品：%+v", m)
		}
	}
	if len(rep.Unidentified) != 0 {
		t.Fatalf("chrome/svchost 不该进待确认栏：%v", rep.Unidentified)
	}
	for _, m := range rep.Matches {
		if m.Token == "" || m.Line == "" {
			t.Fatalf("命中必须带依据（进程名与原始行）：%+v", m)
		}
	}
	if !strings.Contains(rep.Summary(), "识别到终端安全产品") {
		t.Fatalf("结论措辞不对：%s", rep.Summary())
	}
}

// 精确匹配，不是子串：msmpengfoo 不该命中 Defender，jenkins-agent 不该被当成防护。
func TestIdentifyEndpointSecurityNoSubstringMatches(t *testing.T) {
	out := strings.Join([]string{
		`"msmpengfoo.exe","1","Services","0","1 K"`,
		`"jenkins-agent.exe","2","Services","0","1 K"`,
		`"notepad.exe","3","Services","0","1 K"`,
	}, "\n")
	rep := IdentifyEndpointSecurity("windows", out)
	if len(rep.Matches) != 0 {
		t.Fatalf("不该有任何命中：%+v", rep.Matches)
	}
	if rep.Empty {
		t.Fatal("读到三行进程，不该算空输入")
	}
	if !strings.Contains(rep.Summary(), "未命中不等于没有防护") {
		t.Fatalf("没命中时要写明签名表是子集：%s", rep.Summary())
	}
}

func TestIdentifyEndpointSecurityServiceNamesAndLinuxPs(t *testing.T) {
	windows := strings.Join([]string{
		"SERVICE_NAME: WinDefend",
		"        TYPE              : 20 WIN32_SHARE_PROCESS",
		"SERVICE_NAME: CSFalconService",
	}, "\n")
	rep := IdentifyEndpointSecurity("windows", windows)
	if !hasProduct(rep, "Microsoft Defender 防病毒") || !hasProduct(rep, "CrowdStrike Falcon") {
		t.Fatalf("服务名形态没识别出来：%+v", matchedProducts(rep))
	}

	linux := strings.Join([]string{
		"  812 clamd          clamd --config /etc/clamav/clamd.conf",
		"  990 nginx          nginx: master process /usr/sbin/nginx",
		" 1024 freshclam      freshclam",
	}, "\n")
	rep2 := IdentifyEndpointSecurity("linux", linux)
	if !hasProduct(rep2, "ClamAV") {
		t.Fatalf("Linux ps 形态没认出 ClamAV：%+v", matchedProducts(rep2))
	}
	for _, m := range rep2.Matches {
		if strings.Contains(strings.ToLower(m.Line), "nginx") {
			t.Fatalf("nginx 被当成安全产品：%+v", m)
		}
	}
}

// 没登记过但像安全产品的名字：进待确认栏，不硬安产品名，也不静默丢掉。
func TestIdentifyEndpointSecurityKeepsUnregisteredNamesForReview(t *testing.T) {
	out := strings.Join([]string{`"SangforEdrAgent.exe","7","Services","0","1 K"`}, "\n")
	rep := IdentifyEndpointSecurity("windows", out)
	if len(rep.Matches) != 0 {
		t.Fatalf("签名表里没有的产品不该被猜出来：%+v", rep.Matches)
	}
	if len(rep.Unidentified) != 1 || !strings.Contains(rep.Unidentified[0], "Sangfor") {
		t.Fatalf("待确认栏没留住它：%v", rep.Unidentified)
	}
	if !strings.Contains(rep.Summary(), "需人工确认") {
		t.Fatalf("结论要写明有待确认项：%s", rep.Summary())
	}
}

// 空输出与只有表头，都不能被写成「没有终端防护」。
func TestIdentifyEndpointSecurityEmptyIsNotAbsence(t *testing.T) {
	for _, tc := range []struct{ name, out string }{
		{"空输出", ""},
		{"只有表头", `"Image Name","PID","Session Name","Session#","Mem Usage"`},
		{"命令失败", "ERROR: Access is denied."},
	} {
		rep := IdentifyEndpointSecurity("windows", tc.out)
		if !rep.Empty {
			t.Fatalf("%s：应判为没读到列表，得到 %+v", tc.name, rep)
		}
		if !strings.Contains(rep.Summary(), "无法判断") {
			t.Fatalf("%s：结论要写明无法判断，得到 %s", tc.name, rep.Summary())
		}
	}
}

func TestPatchReportBaselineHitAndMiss(t *testing.T) {
	out := strings.Join([]string{
		"Host Name:                 DC01",
		"OS Name:                   Microsoft Windows Server 2016 Standard",
		"OS Version:                10.0.14393 N/A Build 14393",
		"System Type:               x64-based PC",
		"Hotfix(s):                 3 Hotfix(s) Installed.",
		"[01]: KB4012212",
		"[02]: KB5009586",
		"[03]: KB5014678",
	}, "\n")
	rep := AnalyzeWindowsPatches(out)
	if rep.Incomplete {
		t.Fatalf("输入完整却被判为不完整：%+v", rep)
	}
	if rep.OSBuild != "10.0.14393" {
		t.Fatalf("OS 版本没取对：%q", rep.OSBuild)
	}
	if len(rep.Installed) != 3 {
		t.Fatalf("已安装补丁条数不对：%v", rep.Installed)
	}
	var ms17, bluekeep PatchItem
	for _, it := range rep.Items {
		switch it.ID {
		case "MS17-010":
			ms17 = it
		case "CVE-2019-0708":
			bluekeep = it
		}
	}
	if ms17.State != "installed" || ms17.Matched != "KB4012212" {
		t.Fatalf("KB4012212 应命中 MS17-010：%+v", ms17)
	}
	if bluekeep.State != "not_seen" {
		t.Fatalf("BlueKeep 该是未命中：%+v", bluekeep)
	}
	summary := rep.Summary()
	if !strings.Contains(summary, "基线命中 MS17-010") {
		t.Fatalf("命中要写出来：%s", summary)
	}
	if !strings.Contains(summary, "待确认") || !strings.Contains(summary, "未命中不等于存在漏洞") {
		t.Fatalf("未命中必须带「待确认」口径：%s", summary)
	}
}

// 累计更新会取代早期 KB 编号：一台打满补丁的机器可能一个基线号都不出现。
// 所以「一个都没命中」只能是要人工确认，不能写成存在永恒之蓝。
func TestPatchReportCumulativeUpdateSupersedesBaselineKB(t *testing.T) {
	out := strings.Join([]string{
		"OS Name:                   Microsoft Windows 10 Pro",
		"OS Version:                10.0.19044 N/A Build 19044",
		"Hotfix(s):                 1 Hotfix(s) Installed.",
		"[01]: KB5031356",
	}, "\n")
	rep := AnalyzeWindowsPatches(out)
	for _, it := range rep.Items {
		if it.State == "installed" {
			t.Fatalf("基线里不该有命中：%+v", it)
		}
	}
	if strings.Contains(rep.Summary(), "存在漏洞") && !strings.Contains(rep.Summary(), "不等于存在漏洞") {
		t.Fatalf("结论不能把未命中写成存在漏洞：%s", rep.Summary())
	}
}

// 拿不到补丁列表时不做任何缺失判断——「没读到」与「不缺」是两件事。
func TestPatchReportIncompleteInputMakesNoClaims(t *testing.T) {
	for _, tc := range []struct{ name, out string }{
		{"空输出", ""},
		{"N/A 占位", "OS Name: X\nHotfix(s): N/A"},
		{"权限不足", "ERROR: Access is denied."},
	} {
		rep := AnalyzeWindowsPatches(tc.out)
		if !rep.Incomplete {
			t.Fatalf("%s：应判为输入不完整：%+v", tc.name, rep)
		}
		if len(rep.Items) != 0 {
			t.Fatalf("%s：不完整时不该产出基线条目：%+v", tc.name, rep.Items)
		}
		if strings.Contains(rep.Summary(), "未命中") {
			t.Fatalf("%s：不完整时不该说未命中：%s", tc.name, rep.Summary())
		}
	}
}

// 三种采集形态都要能取到 KB：systeminfo、wmic qfe、Get-HotFix（含小写）。
func TestPatchReportAcceptsAllThreeFormats(t *testing.T) {
	cases := []string{
		"Hotfix(s): 1 Hotfix(s) Installed.\n[01]: KB4503260",
		"Description,HotFixID,InstalledOn\nSecurity Update,KB4503260,20190812",
		`"Source","Description","HotFixID","InstalledOn"` + "\n" + `"DC01","Update","kb4503260","2019/8/12"`,
	}
	for i, out := range cases {
		rep := AnalyzeWindowsPatches(out)
		if rep.Incomplete || len(rep.Installed) != 1 || rep.Installed[0] != "KB4503260" {
			t.Fatalf("形态 %d 解析不对：%+v", i, rep)
		}
		found := false
		for _, it := range rep.Items {
			if it.ID == "CVE-2019-0708" && it.State == "installed" {
				found = true
			}
		}
		if !found {
			t.Fatalf("形态 %d 没命中 BlueKeep 基线：%+v", i, rep.Items)
		}
	}
}

func TestPatchAdvisoryIDsAreListed(t *testing.T) {
	ids := strings.Join(PatchAdvisoryIDs(), ",")
	for _, want := range []string{"MS17-010", "CVE-2019-0708", "CVE-2020-1472", "CVE-2021-34527"} {
		if !strings.Contains(ids, want) {
			t.Fatalf("基线少了 %s：%s", want, ids)
		}
	}
}
