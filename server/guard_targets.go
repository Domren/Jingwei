package server

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/jingwei/guard"
	"github.com/Autumn-27/jingwei/scanner"
)

// 把目标策略这道闸用到**界面直接建的确定性任务**上（漏扫、弱口令检测）。
//
// 为什么必须补：guard 原先只挂在 agent 工具钩子与内网执行上，于是「平台资产禁令」与
// 「客户授权清单」事实上只对 LLM 生效——从漏扫页或弱口令检测页点一下新建，目标不在授权
// 范围内也照打。漏扫至少有资产禁令兜着（`scanTargetBlockReason`），**弱口令检测此前什么都不问**，
// 而它主动发认证包，打错地方不只是越界，还会把别人家的账号打进锁定。
//
// 三档语义与工具侧完全一致：strict 拒绝、warn 放行但把话留在日志里、off 不检查。
// 确定性任务在 tasks 表里没有对应行，所以任务编号传 0——资产禁令与客户授权本来就是平台级的。
func guardCheckTargets(pol guard.TargetPolicy, urls, hosts []string) (deny, warn string) {
	if pol == nil || (len(urls) == 0 && len(hosts) == 0) {
		return "", ""
	}
	mode := strings.ToLower(strings.TrimSpace(pol.Mode()))
	if mode == "off" {
		return "", ""
	}
	verdict, reason := pol.Check(0, urls, hosts)
	if verdict != guard.ScopeOut {
		return "", ""
	}
	if reason = strings.TrimSpace(reason); reason == "" {
		reason = "目标不在平台允许的测试范围内"
	}
	if mode != "strict" {
		return "", "目标防护当前为告警模式，已放行但记录在案：" + reason
	}
	return reason, ""
}

// guardProbeTargets 把用户输入的目标摊成 guard 认得的形状：URL 归 URL，域名/IP 归 host，
// CIDR 摊成里面的地址（授权规则里的 CIDR 只有拿具体地址去比才判得出包含关系）。
func guardProbeTargets(targets []scanner.Target) (urls, hosts []string, err error) {
	seenHost, seenURL := map[string]bool{}, map[string]bool{}
	for _, t := range targets {
		if t.Kind == scanner.KindCIDR {
			ips, e := cidrIPs(t.Host)
			if e != nil {
				return nil, nil, fmt.Errorf("网段 %s 展开失败：%v", t.Host, e)
			}
			for _, ip := range ips {
				if !seenHost[ip] {
					seenHost[ip] = true
					hosts = append(hosts, ip)
				}
			}
			continue
		}
		domains, ips, us := t.InterceptCandidates()
		for _, u := range us {
			if !seenURL[u] {
				seenURL[u] = true
				urls = append(urls, u)
			}
		}
		for _, h := range append(domains, ips...) {
			if !seenHost[h] {
				seenHost[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	return urls, hosts, nil
}

// admissionPolicy 取准入检查用的目标策略：现场新建，不用进程级那个。
//
// 进程级策略把授权清单缓存 30 秒，图的是高频目标检查不必每条都查库。准入检查恰好是
// 缓存最不该出现的地方：它低频，却总发生在「授权清单刚刚改过」的那一刻——补完授权就
// 点新建、改完范围就重跑任务。更危险的是空清单也会被缓存：平台刚起来还没有任何授权时
// 按老语义放行过一次，随后操作员补上授权，接下来 30 秒内对着范围外主机照样不拦，
// 而认证包一旦发出去就收不回来。没有数据库时仍退回进程级策略（可能为 nil），
// 保持「没有策略就没有这一层」的老语义。
func (s *Server) admissionPolicy() guard.TargetPolicy {
	if s == nil || s.m == nil {
		return nil
	}
	if s.m.pg != nil {
		return newGuardTargetPolicy(s.m.pg)
	}
	return s.m.guardPolicy
}

// invalidateGuardAuthorizations 让进程级目标策略立刻重读授权清单。
//
// 准入检查（创建任务、执行前复核）本来就是现场新建策略源，不看这份缓存；这里管的是
// 另一批消费者——agent 工具与资产禁令那几路共用进程级策略，它们要等 30 秒才看见
// 操作员刚补的授权。
func (s *Server) invalidateGuardAuthorizations() {
	if s == nil || s.m == nil {
		return
	}
	if pol, ok := s.m.guardPolicy.(*guardTargetPolicy); ok {
		pol.invalidateAuthorizations()
	}
}

// guardInputTargets 把用户输入的目标摊开、过一遍平台策略。创建任务与续扫准入共用
// 同一段判断，两条路径给出不同的准入条件就等于没有准入条件。
func (s *Server) guardInputTargets(targets []scanner.Target) (deny, warn string) {
	urls, hosts, err := guardProbeTargets(targets)
	if err != nil {
		return err.Error(), ""
	}
	return guardCheckTargets(s.admissionPolicy(), urls, hosts)
}
