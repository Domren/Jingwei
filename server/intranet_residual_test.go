package server

import "testing"

// G1：台账外残留的过滤口径——台账里的路径与精卫标记必须被排除，其余原样列出。
func TestLedgerExternalFilter(t *testing.T) {
	output := "*/5 * * * * /usr/local/bin/jingwei-beacon\n" +
		"0 3 * * * /opt/app/backup.sh\n" +
		"# comment line\n" +
		"-rw-r--r-- 1 root root 12 Jan 1 /tmp/.hidden_tool\n" +
		"/usr/bin/cleanup-task\n"
	needles := []string{"jingwei", "/tmp/.hidden_tool"}
	got := ledgerExternalFilter(output, "cron", needles)
	if len(got) != 2 {
		t.Fatalf("got = %+v", got)
	}
	if got[0] != "cron: 0 3 * * * /opt/app/backup.sh" || got[1] != "cron: /usr/bin/cleanup-task" {
		t.Fatalf("got = %+v", got)
	}
}
