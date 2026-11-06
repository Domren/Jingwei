package db

import (
	"strings"
	"testing"
)

// 痕迹矩阵的知识库（G4）必须覆盖每一种维持手段：漏掉一种，报告就会对那一种留白，
// 而读者会把留白读成「没有痕迹」。
func TestArtifactTraceProfilesCoverEveryKind(t *testing.T) {
	kinds := []string{
		IntranetArtifactFile, IntranetArtifactCron, IntranetArtifactSystemd, IntranetArtifactUserSystemd,
		IntranetArtifactAt, IntranetArtifactProfile, IntranetArtifactSSHKey, IntranetArtifactSchtasks,
		IntranetArtifactRegistry, IntranetArtifactService, IntranetArtifactWMI, IntranetArtifactStartup,
		IntranetArtifactPHPUserINI, IntranetArtifactPHPHtaccess, IntranetArtifactOther,
		ArtifactTraceMemshell, ArtifactTraceTunnel,
	}
	for _, k := range kinds {
		p, ok := ArtifactTraceProfileFor(k)
		if !ok {
			t.Errorf("kind %q 没有痕迹档案", k)
			continue
		}
		if p.Name == "" || len(p.Traces) == 0 || strings.TrimSpace(p.Verify) == "" {
			t.Errorf("kind %q 的档案不完整：%+v", k, p)
		}
		// other 与隧道之外的手段都必须说清「撤销后还剩什么」；说不清就写「未知」，不能空着。
		if len(p.Residue) == 0 {
			t.Errorf("kind %q 没有列出撤销后仍存在的痕迹", k)
		}
		for _, line := range append(append([]string{}, p.Traces...), p.Residue...) {
			if strings.TrimSpace(line) == "" {
				t.Errorf("kind %q 的档案里有空行", k)
			}
		}
	}
	// 台账 kind 与档案 kind 必须一一对上：新增 kind 只加常量、不加档案，这里就会红。
	for _, k := range []string{IntranetArtifactFile, IntranetArtifactCron, IntranetArtifactSystemd,
		IntranetArtifactUserSystemd, IntranetArtifactAt, IntranetArtifactProfile, IntranetArtifactSSHKey,
		IntranetArtifactSchtasks, IntranetArtifactRegistry, IntranetArtifactService, IntranetArtifactWMI,
		IntranetArtifactStartup, IntranetArtifactPHPUserINI, IntranetArtifactPHPHtaccess, IntranetArtifactOther} {
		if !validIntranetArtifactKind(k) {
			t.Errorf("用例里的 kind %q 已不在台账 kind 表中，请同步", k)
		}
	}
	if _, ok := ArtifactTraceProfileFor("no-such-kind"); ok {
		t.Error("未知 kind 不该拿到一个档案")
	}
	if len(ArtifactTraceKinds()) != len(kinds) {
		t.Errorf("档案数量与用例不符：%d vs %d", len(ArtifactTraceKinds()), len(kinds))
	}
}

// 半持久化两种形态的验证必须同时看「标记块」和「载荷文件」：只验一个会漏掉
// 悬空引用（块还在、文件没了）与可重新指向的块（文件还在、块没了）。
func TestPHPTraceProfileRequiresBothHalves(t *testing.T) {
	for _, k := range []string{IntranetArtifactPHPUserINI, IntranetArtifactPHPHtaccess} {
		p, ok := ArtifactTraceProfileFor(k)
		if !ok {
			t.Fatalf("kind %q 没有档案", k)
		}
		if !strings.Contains(p.Verify, "两项都要验") && !(strings.Contains(p.Verify, "标记块") && strings.Contains(p.Verify, "载荷文件")) {
			t.Errorf("%s 的验证方式没有同时要求标记块与载荷文件：%q", k, p.Verify)
		}
	}
}
