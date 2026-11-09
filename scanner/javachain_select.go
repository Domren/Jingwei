package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// E3 B 段：按目标 JDK 版本决定 JNDI/gadget 投递路线。
//
// 这里只做「根据版本做决策并给出证据」，不宣称任何一条链在真实目标上可用：
// 判定依据是 JDK 的公开默认值（远程类加载与 LDAP 反序列化的开关），要真正
// 证明 exec 级成功仍需低版本 JDK 靶机（E1），本版不假验证。

// JNDIRoute 是 JNDI 投递能走的路子。
type JNDIRoute string

const (
	// JNDIRouteRemoteClass 依赖目标从 LDAP 回连加载远程类（trustURLCodebase=true，
	// 仅老版本默认开启）。
	JNDIRouteRemoteClass JNDIRoute = "jndi_remote_class"
	// JNDIRouteLocalGadget 依赖目标本机 classpath 里已有的 gadget（远程类加载已关，
	// LDAP 反序列化是否可行取决于 trustSerialData，本平台不做「一定可用」的结论）。
	JNDIRouteLocalGadget JNDIRoute = "jndi_local_gadget"
	// JNDIRouteLocalOnly 目标 JDK 已强封装，只考虑本机 gadget，且反射链可能因
	// --add-opens 缺失而失败。
	JNDIRouteLocalOnly JNDIRoute = "local_gadget_only"
	// JNDIRouteUnknown 没拿到版本，不做任何「远程类加载可用」的判断。
	JNDIRouteUnknown JNDIRoute = "unknown"
)

// JavaRuntime is a parsed java.version / java.specification.version value.
type JavaRuntime struct {
	Raw    string
	Major  int
	Update int // 8u191 → 191；未知为 0
}

// Known reports whether a usable major version was parsed.
func (j JavaRuntime) Known() bool { return j.Major > 0 }

func (j JavaRuntime) String() string {
	if !j.Known() {
		return "unknown"
	}
	if j.Major == 8 && j.Update > 0 {
		return fmt.Sprintf("%d(update %d)", j.Major, j.Update)
	}
	return strconv.Itoa(j.Major)
}

// ParseJavaVersion accepts the shapes a probe actually returns:
// "1.8.0_392", "1.8.0_191-b12", "8u191", "11.0.21", "17.0.9+9", "17", "21".
func ParseJavaVersion(raw string) JavaRuntime {
	rt := JavaRuntime{Raw: strings.TrimSpace(raw)}
	s := strings.ToLower(rt.Raw)
	if s == "" {
		return rt
	}
	s = strings.TrimPrefix(s, "jdk")
	s = strings.TrimPrefix(s, "java version ")
	s = strings.Trim(s, `"`)
	// 1.8.0_392 / 1.7.0_80
	if strings.HasPrefix(s, "1.") {
		rest := s[2:]
		major, tail := leadingInt(rest)
		if major > 0 {
			rt.Major = major
			if i := strings.IndexAny(tail, "_b"); i >= 0 && tail[i] == '_' {
				if upd, _ := leadingInt(tail[i+1:]); upd > 0 {
					rt.Update = upd
				}
			}
			return rt
		}
	}
	// 8u191
	if major, tail := leadingInt(s); major > 0 {
		rt.Major = major
		if strings.HasPrefix(tail, "u") {
			if upd, _ := leadingInt(tail[1:]); upd > 0 {
				rt.Update = upd
			}
		}
		return rt
	}
	return rt
}

// leadingInt returns the leading decimal run and the remainder.
func leadingInt(s string) (int, string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, s
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, s
	}
	return n, s[i:]
}

// JavaChainPlan is the routing decision plus the evidence behind it.
type JavaChainPlan struct {
	Route            JNDIRoute `json:"route"`
	AllowRemoteClass bool      `json:"allow_remote_class"`
	PreferLocalChain bool      `json:"prefer_local_chain"`
	Reason           string    `json:"reason"`
	Warnings         []string  `json:"warnings,omitempty"`
}

// PlanJavaChain decides the JNDI delivery route for a probed JDK version.
//
// 判定阈值来自 JDK 公开默认值：
//   - 8u191 / 7u201 / 6u211 起，LDAP 远程 codebase 默认关闭（trustURLCodebase=false）；
//   - 同一批版本起 trustSerialData 默认 false，LDAP 里塞序列化数据不再自动反序列化；
//   - 16 起强封装（JEP 396），17 起默认 deny，反射型 gadget 需要 --add-opens。
//
// 这是「预期」，不是验证结论：真正确认要靠靶机。
func PlanJavaChain(rt JavaRuntime) JavaChainPlan {
	if !rt.Known() {
		return JavaChainPlan{
			Route:    JNDIRouteUnknown,
			Reason:   "未探测到目标 JDK 版本，按通用顺序尝试；不对远程类加载是否可用下结论",
			Warnings: []string{"JDK 版本未知，若目标是 8u191+/11+/17+，远程类加载大概率已被默认关闭"},
		}
	}
	switch {
	case rt.Major <= 6:
		if rt.Update >= 211 {
			return localGadgetPlan(rt, "6u211 起 trustURLCodebase 默认关闭")
		}
		return remoteClassPlan(rt, "6u211 之前远程类加载默认开启")
	case rt.Major == 7:
		if rt.Update >= 201 {
			return localGadgetPlan(rt, "7u201 起 trustURLCodebase 默认关闭")
		}
		return remoteClassPlan(rt, "7u201 之前远程类加载默认开启")
	case rt.Major == 8:
		if rt.Update >= 191 {
			return localGadgetPlan(rt, "8u191 起 trustURLCodebase 与 trustSerialData 默认关闭")
		}
		if rt.Update == 0 {
			plan := localGadgetPlan(rt, "只知道是 JDK 8 但不知道 update 号，按 8u191+ 的保守口径选本地链")
			plan.Warnings = append(plan.Warnings, "补到具体 update（如 1.8.0_392）才能判断远程类加载是否默认可用")
			return plan
		}
		return remoteClassPlan(rt, "8u191 之前远程类加载默认开启")
	case rt.Major >= 16:
		plan := localGadgetPlan(rt, fmt.Sprintf("JDK %d 已强封装（JEP 396），远程类加载与多数反射链默认不可用", rt.Major))
		plan.Route = JNDIRouteLocalOnly
		plan.Warnings = append(plan.Warnings, "本机 gadget 若依赖反射访问 JDK 内部类，需目标以 --add-opens 启动才可能成功")
		return plan
	default:
		// 9–15：远程类加载默认关闭，trustSerialData 默认 false。
		return localGadgetPlan(rt, fmt.Sprintf("JDK %d 远程类加载默认关闭", rt.Major))
	}
}

func remoteClassPlan(rt JavaRuntime, why string) JavaChainPlan {
	return JavaChainPlan{
		Route:            JNDIRouteRemoteClass,
		AllowRemoteClass: true,
		Reason:           fmt.Sprintf("JDK %s：%s，可优先尝试远程类加载链", rt.String(), why),
	}
}

func localGadgetPlan(rt JavaRuntime, why string) JavaChainPlan {
	return JavaChainPlan{
		Route:            JNDIRouteLocalGadget,
		PreferLocalChain: true,
		Reason:           fmt.Sprintf("JDK %s：%s，优先本机 gadget 链；远程类加载不作为可行路线", rt.String(), why),
	}
}

// OrderJavaChainsPresets puts the presets that fit the plan first, keeping the
// caller's order as the tie-break. It never drops a preset: the plan is an
// expectation, and a target may be hardened or customized against JDK defaults,
// so the remaining presets stay as fallbacks.
func OrderJavaChainsPresets(plan JavaChainPlan, presets []JavaChainsPreset) []JavaChainsPreset {
	out := append([]JavaChainsPreset(nil), presets...)
	if !plan.PreferLocalChain {
		return out
	}
	sort.SliceStable(out, func(i, j int) bool {
		return localFirstRank(out[i]) < localFirstRank(out[j])
	})
	return out
}

// localFirstRank 在「优先本地链」时把 outbound-jndi 排到后面。
func localFirstRank(p JavaChainsPreset) int {
	base := 0
	switch p.Intent {
	case "command-exec":
		base = 1
	default:
		base = 2
	}
	if p.Intent == "outbound-jndi" {
		return base + 100
	}
	return base
}
