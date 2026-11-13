package db

import "testing"

// R19 序 5：授权粒度必选项的校验与落库。

func TestNormalizeScopeGranularity(t *testing.T) {
	for _, in := range []string{"ip_port", "IP_PORT", " ip_port "} {
		got, err := NormalizeScopeGranularity(in)
		if err != nil || got != ScopeGranularityIPPort {
			t.Fatalf("ip_port variants must normalize, got %q err=%v", got, err)
		}
	}
	if got, err := NormalizeScopeGranularity("By_IP"); err != nil || got != ScopeGranularityByIP {
		t.Fatalf("by_ip must normalize, got %q err=%v", got, err)
	}
	if _, err := NormalizeScopeGranularity(""); err == nil {
		t.Fatal("empty must be rejected（必选项）")
	}
	if _, err := NormalizeScopeGranularity("host_level"); err == nil {
		t.Fatal("unknown must be rejected, not silently defaulted")
	}
}

// 创建时带粒度 → 回读一致；不带 → DB 层兜底 by_ip（编排/旧包装路径），绝不落空串。
func TestCreateTaskScopeGranularityRoundTrip(t *testing.T) {
	d := testDB(t)
	pt, err := d.CreateTaskWithOptions("R19 粒度回读", "目标", TaskCreateOptions{ScopeGranularity: ScopeGranularityIPPort})
	if err != nil {
		t.Fatal(err)
	}
	find := func(id int64) *Task {
		tasks, err := d.ListTasks()
		if err != nil {
			t.Fatal(err)
		}
		for _, tt := range tasks {
			if tt.ID == id {
				return tt
			}
		}
		return nil
	}
	strict := find(pt.ID)
	if strict == nil {
		t.Fatalf("task %d not listed", pt.ID)
	}
	if strict.ScopeGranularity != ScopeGranularityIPPort {
		t.Fatalf("granularity lost on read-back, got %q", strict.ScopeGranularity)
	}

	pt2, err := d.CreateTaskWithOptions("R19 粒度缺省", "目标", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fallback := find(pt2.ID)
	if fallback == nil {
		t.Fatalf("task %d not listed", pt2.ID)
	}
	if fallback.ScopeGranularity != ScopeGranularityByIP {
		t.Fatalf("unset granularity must default to by_ip, got %q", fallback.ScopeGranularity)
	}
}
