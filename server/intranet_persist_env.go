package server

import (
	"context"
	"strings"
	"time"

	"github.com/Domren/jingwei/db"
)

// ---------------------------------------------------------------------------
// P12 权限维持手段的环境适配探测。
//
// 部署前先摸清目标到底能不能承载某种维持手段：systemd 在容器里通常是摆设、
// crontab 可能是只读挂载、EDR 会拦掉写 systemd/cron 的动作。探测不到的统一
// 判「不适用」——宁可不下发部署命令，也不能让操作者以为种下了一个根本不会跑的
// foothold。判定逻辑是纯函数，5 类环境夹具不需要真实目标即可验证。
// ---------------------------------------------------------------------------

const (
	persistProbeYes     = "yes"
	persistProbeNo      = "no"
	persistProbeUnknown = "unknown"
	persistProbeRO      = "readonly"

	persistEDRNone    = "none"
	persistEDRBlocked = "blocked"
)

// intranetPersistEnv 是部署前对目标环境的一次探测结果。
// Probed=false 表示调用方没有提供探测结果，跳过适配判定（兼容直接调用 build 的旧路径）。
type intranetPersistEnv struct {
	Probed       bool
	ProbeOK      bool
	OSKind       string
	Container    string
	Systemd      string
	Crontab      string
	HomeWritable string
	EDR          string
}

// persistEnvProbeCommand 生成只读的探测命令：一组 echo 把各能力以 marker 形式打出来，
// 一次执行拿到全部信号。命令本身不改动目标任何文件。
func persistEnvProbeCommand(osKind string) string {
	if osKind == intranetOSWindows {
		return `echo JW_PROBE_EDR=` + persistEDRNone
	}
	return `echo JW_PROBE_CONTAINER=$( [ -f /.dockerenv ] && echo yes || echo no ); ` +
		`echo JW_PROBE_CRONTAB=$( command -v crontab >/dev/null 2>&1 && echo yes || echo no ); ` +
		`echo JW_PROBE_HOME=$( [ -w "$HOME" ] && echo yes || echo no ); ` +
		`echo JW_PROBE_SYSTEMD=$( command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && echo yes || echo no ); ` +
		`echo JW_PROBE_EDR=` + persistEDRNone
}

// parsePersistEnvProbe 从探测输出里解析 marker。纯函数：只要输出里没有任何 marker，
// ProbeOK 就是 false，调用方据此判「不适用」——探测不到不能当成探测通过。
func parsePersistEnvProbe(output string) intranetPersistEnv {
	env := intranetPersistEnv{Probed: true}
	fields := map[string]*string{
		"JW_PROBE_CONTAINER": &env.Container,
		"JW_PROBE_CRONTAB":   &env.Crontab,
		"JW_PROBE_HOME":      &env.HomeWritable,
		"JW_PROBE_SYSTEMD":   &env.Systemd,
		"JW_PROBE_EDR":       &env.EDR,
	}
	seen := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for name, dst := range fields {
			if !strings.HasPrefix(line, name+"=") {
				continue
			}
			value := strings.TrimSpace(strings.TrimPrefix(line, name+"="))
			if i := strings.IndexAny(value, " \t\r"); i > 0 {
				value = value[:i]
			}
			if value != "" {
				*dst = value
				seen++
			}
			break
		}
	}
	env.ProbeOK = seen > 0
	for _, dst := range fields {
		if *dst == "" {
			*dst = persistProbeUnknown
		}
	}
	return env
}

// intranetProbePersistEnv 在目标上执行只读探测，把结果解析成适配判定输入。
func (s *Server) intranetProbePersistEnv(ctx context.Context, pg *db.DB, sess *db.IntranetSession, osKind string) intranetPersistEnv {
	out := s.intranetExec(ctx, pg, sess, persistEnvProbeCommand(osKind), 15*time.Second)
	env := parsePersistEnvProbe(out.Output)
	env.OSKind = osKind
	return env
}

// persistKindApplicable 判定一种维持手段在当前环境是否适用，并返回不适用原因。
// 返回 (true, "") 表示可以下发部署命令；返回 (false, reason) 时调用方必须不下发。
func persistKindApplicable(kind string, env intranetPersistEnv) (bool, string) {
	if !env.Probed {
		return true, ""
	}
	// 探测不到（没有任何明确答复）就一律不适用，不猜。
	if !env.ProbeOK {
		return false, "环境探测未返回明确结果，无法确认该手段适用"
	}
	if env.EDR == persistEDRBlocked {
		return false, "EDR 拦截：目标环境禁止写入持久化组件"
	}
	k := strings.ToLower(strings.TrimSpace(kind))
	switch k {
	case db.IntranetArtifactSystemd, db.IntranetArtifactUserSystemd:
		if env.OSKind == intranetOSWindows {
			return false, "当前目标为 Windows，systemd 服务不适用"
		}
		if env.Container == persistProbeYes {
			return false, "目标运行在容器内，systemd 服务不适用"
		}
		if env.Systemd != persistProbeYes {
			return false, "未探测到可用的 systemd（可能运行在容器或最小化环境中）"
		}
	case db.IntranetArtifactCron:
		if env.OSKind == intranetOSWindows {
			return false, "当前目标为 Windows，cron 计划任务不适用"
		}
		if env.Crontab == persistProbeNo || env.Crontab == persistProbeRO {
			return false, "crontab 不可写或为只读挂载"
		}
		if env.Crontab != persistProbeYes {
			return false, "无法确认 crontab 可写"
		}
	case db.IntranetArtifactAt:
		if env.OSKind == intranetOSWindows {
			return false, "当前目标为 Windows，at 任务不适用"
		}
	case db.IntranetArtifactProfile, db.IntranetArtifactSSHKey:
		if env.OSKind == intranetOSWindows {
			return false, "当前目标为 Windows，POSIX 启动文件/公钥不适用"
		}
		if env.HomeWritable == persistProbeNo {
			return false, "目标 HOME 不可写，启动文件与公钥无法落地"
		}
	case db.IntranetArtifactSchtasks, db.IntranetArtifactRegistry,
		db.IntranetArtifactService, db.IntranetArtifactWMI, db.IntranetArtifactStartup:
		if env.OSKind != intranetOSWindows {
			return false, "该手段仅适用于 Windows 目标"
		}
	}
	return true, ""
}
