package server

import (
	"context"
	"fmt"
	"log"
	"time"
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
