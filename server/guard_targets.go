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

// targetPolicy 取进程级目标策略。没有策略源（未接数据库的构造路径）时返回 nil，
// 调用方据此放行——与 guard 自己的「没有策略就没有这一层」保持一致。
func (s *Server) targetPolicy() guard.TargetPolicy {
	if s == nil || s.m == nil {
		return nil
	}
	return s.m.guardPolicy
}
