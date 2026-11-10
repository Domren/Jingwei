package agent

import (
	"context"

	"github.com/Autumn-27/jingwei/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// FindingShotter is the optional capability of a recorder: render the forensic
// panel of a recorded finding into an evidence screenshot. Hosts that can
// render (the evidence store can) implement it; the agent treats it as a
// best-effort extra and never blocks a confirmed finding on it.
type FindingShotter interface {
	CaptureShot(context.Context, int64) (int64, error)
}

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
