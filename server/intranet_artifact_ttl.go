package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/jingwei/notify"
)

const (
	intranetArtifactExpiryInterval = time.Minute
	intranetArtifactExpiryRetry    = 10 * time.Minute
	intranetArtifactExpiryBatch    = 20
)

// runIntranetArtifactExpiry revokes ledger entries whose TTL elapsed. Failed
// revocations stay active and retry with a cooldown; a single transition event
// per artifact avoids filling the session log with repeating failures.
func (s *Server) runIntranetArtifactExpiry(ctx context.Context) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	lastAttempt := map[int64]time.Time{}
	reported := map[int64]bool{}
	ticker := time.NewTicker(intranetArtifactExpiryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.intranetArtifactExpirySweep(ctx, lastAttempt, reported)
			s.intranetArtifactExpiryNoticeSweep(ctx)
		}
	}
}

// intranetArtifactExpiryNoticeSweep 在到期前 24 小时推一次告警（G2）。
// 用 expiry_notified_at 做幂等标记：推送失败不标记，下个周期重试；
// 事件走通知渠道队列，投递失败还有既有的重试与记录。
func (s *Server) intranetArtifactExpiryNoticeSweep(ctx context.Context) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	arts, err := pg.ListArtifactsExpiringSoon(24*time.Hour, 100)
	if err != nil {
		log.Printf("[intranet][ttl] 查询即将到期落地物失败: %v", err)
		return
	}
	for _, art := range arts {
		if ctx.Err() != nil {
			return
		}
		name := art.Name
		if name == "" {
			name = art.Path
		}
		exp := ""
		if art.ExpiresAt != nil {
			exp = art.ExpiresAt.Format("2006-01-02 15:04")
		}
		taskID := int64(0)
		if art.TaskID != nil {
			taskID = *art.TaskID
		}
		summary := fmt.Sprintf("落地物 #%d（%s · %s）将于 %s 到期，到期后会尝试自动撤销；请确认是否仍需维持。",
			art.ID, art.Kind, name, exp)
		if _, err := pg.AddNotificationEvent(ctx, notify.EventArtifactExpiring, 0, notify.Snapshot{
			Kind: notify.EventArtifactExpiring, TaskID: taskID,
			Name: "落地物即将到期", VulnClass: "system", Severity: "high", Summary: summary,
		}); err != nil {
			log.Printf("[intranet][ttl] 写入到期告警事件失败 #%d: %v", art.ID, err)
			continue
		}
		if err := pg.MarkArtifactExpiryNotified(art.ID); err != nil {
			log.Printf("[intranet][ttl] 标记到期告警失败 #%d: %v", art.ID, err)
		}
	}
}

func (s *Server) intranetArtifactExpirySweep(ctx context.Context, lastAttempt map[int64]time.Time, reported map[int64]bool) {
	pg := s.m.pg
	if pg == nil {
		return
	}
	arts, err := pg.ListExpiredIntranetArtifacts(time.Now(), intranetArtifactExpiryBatch)
	if err != nil {
		log.Printf("[intranet][ttl] 扫描到期落地物失败: %v", err)
		return
	}
	now := time.Now()
	for _, art := range arts {
		if ctx.Err() != nil {
			return
		}
		if last, ok := lastAttempt[art.ID]; ok && now.Sub(last) < intranetArtifactExpiryRetry {
			continue
		}
		lastAttempt[art.ID] = now
		if art.SessionID == nil || *art.SessionID <= 0 {
			// PHP prepend artifacts have no session; their metadata still points
			// at a webshell the runner can use, so only skip when neither path
			// is available.
			if _, rerr := s.intranetArtifactRunner(ctx, pg, art, 0); rerr != nil {
				if !reported[art.ID] {
					log.Printf("[intranet][ttl] 落地物 #%d 已到期但没有可用会话或 webshell，无法自动撤销：%v", art.ID, rerr)
					reported[art.ID] = true
				}
				continue
			}
		}
		_, _, _, revoked, rerr := s.intranetRevokeArtifact(ctx, pg, art.ID, 0)
		if revoked {
			delete(lastAttempt, art.ID)
			delete(reported, art.ID)
			if art.SessionID != nil && *art.SessionID > 0 {
				_ = pg.AddIntranetSessionEvent(*art.SessionID, "artifact",
					fmt.Sprintf("TTL 到期自动撤销落地物 #%d", art.ID),
					"撤销命令已执行并通过验证，痕迹消失", false)
			}
			log.Printf("[intranet][ttl] 落地物 #%d 已到期并自动撤销", art.ID)
			continue
		}
		detail := "撤销未通过验证"
		if rerr != nil {
			detail = rerr.Error()
		}
		if !reported[art.ID] {
			reported[art.ID] = true
			if art.SessionID != nil && *art.SessionID > 0 {
				_ = pg.AddIntranetSessionEvent(*art.SessionID, "artifact",
					fmt.Sprintf("TTL 到期自动撤销失败 #%d", art.ID), truncateIntranetOutput(detail, 2000), true)
			}
		}
		log.Printf("[intranet][ttl] 落地物 #%d 自动撤销失败: %s", art.ID, detail)
	}
	for id, at := range lastAttempt {
		if now.Sub(at) > 24*time.Hour {
			delete(lastAttempt, id)
		}
	}
}
