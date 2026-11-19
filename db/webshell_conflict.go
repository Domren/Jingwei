package db

import "context"

// WebshellDeployConflict 是 P18 的部署前冲突记录：注入前发现落地路径已有文件
// 或可疑内容时落一条，转人工核对授权方资产，绝不自动覆盖。
type WebshellDeployConflict struct {
	ID        int64  `json:"id"`
	TaskID    *int64 `json:"task_id,omitempty"`
	LandURL   string `json:"land_url"`
	UploadURL string `json:"upload_url"`
	Marker    string `json:"marker"`
	Detail    string `json:"detail"`
	Status    string `json:"status"`
	Resolved  bool   `json:"resolved"`
}

// AddWebshellDeployConflict 落一条待人工的冲突记录，返回其 id。
func (d *DB) AddWebshellDeployConflict(taskID *int64, landURL, uploadURL, marker, detail string) (int64, error) {
	return d.AddWebshellDeployConflictContext(context.Background(), taskID, landURL, uploadURL, marker, detail)
}

// AddWebshellDeployConflictContext is the cancellable form.
func (d *DB) AddWebshellDeployConflictContext(ctx context.Context, taskID *int64, landURL, uploadURL, marker, detail string) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `INSERT INTO webshell_deploy_conflicts
	(task_id, land_url, upload_url, marker, detail) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		taskID, landURL, uploadURL, marker, detail).Scan(&id)
	return id, err
}

// ListWebshellDeployConflicts 列出冲突记录；unresolvedOnly 时只看待人工的。
func (d *DB) ListWebshellDeployConflicts(unresolvedOnly bool, limit int) ([]*WebshellDeployConflict, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	where := ""
	if unresolvedOnly {
		where = " WHERE resolved=false"
	}
	rows, err := d.Query(`SELECT id, task_id, land_url, upload_url, marker, detail, status, resolved
		FROM webshell_deploy_conflicts`+where+` ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*WebshellDeployConflict{}
	for rows.Next() {
		c := &WebshellDeployConflict{}
		if err := rows.Scan(&c.ID, &c.TaskID, &c.LandURL, &c.UploadURL, &c.Marker, &c.Detail, &c.Status, &c.Resolved); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ResolveWebshellDeployConflict 把一条冲突标记人工处置完毕。
func (d *DB) ResolveWebshellDeployConflict(id int64) error {
	_, err := d.Exec(`UPDATE webshell_deploy_conflicts SET resolved=true, status='resolved' WHERE id=$1`, id)
	return err
}
