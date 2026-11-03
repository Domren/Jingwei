package db

import (
	"testing"
)

func TestJavaMemshellLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	shell, err := d.CreateWebshell(WebshellInput{
		Name:      "memshell-test-parent",
		URL:       "http://127.0.0.1:1/shell.jsp",
		ShellType: "jsp",
		Protocol:  "v2",
		Secret:    "v1:test",
		Carrier:   "X-MemTestCarrier",
		Target:    "memshell-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	shellID := shell.ID

	ms, err := d.CreateJavaMemshell(JavaMemshellInput{
		WebshellID: &shellID,
		Type:       "filter",
		Name:       "ms_test_filter",
		Path:       "/static/memtest.js",
		URL:        "http://127.0.0.1:1/static/memtest.js",
		Secret:     "v1:sealed",
		Carrier:    "X-MemTestCarrier",
		Target:     "memshell-test",
		Container:  "tomcat",
		ServletAPI: "javax",
		Status:     "alive",
		Note:       "unit test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM managed_resources WHERE kind='memshell' AND metadata->>'memshell_id'=$1`, ms.ID)
		_, _ = d.DeleteJavaMemshell(ms.ID)
		_, _ = d.DeleteWebshell(shellID)
	})

	got, err := d.GetJavaMemshell(ms.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != ms.Name || got.Type != "filter" || !got.HasSecret || got.Secret != "v1:sealed" {
		t.Fatalf("unexpected memshell: %+v", got)
	}

	list, total, err := d.ListJavaMemshells(JavaMemshellFilter{WebshellID: shellID, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(list) != 1 || list[0].ID != ms.ID {
		t.Fatalf("list active: total=%d len=%d", total, len(list))
	}

	n, err := d.CountJavaMemshellsByWebshell(shellID)
	if err != nil || n != 1 {
		t.Fatalf("count=%d err=%v", n, err)
	}

	if err := d.UpdateJavaMemshellProbe(ms.ID, "alive", "tomcat", "jakarta", "probe ok"); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateJavaMemshellState(ms.ID, "dead", "last output", "checked"); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetJavaMemshell(ms.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServletAPI != "jakarta" || got.Status != "dead" || got.LastOutput != "last output" || got.LastChecked == nil {
		t.Fatalf("state not updated: %+v", got)
	}

	res, err := d.RegisterManagedResource(ManagedResourceInput{
		Kind:     ManagedKindMemshell,
		Name:     ms.Name,
		Endpoint: ms.URL,
		Target:   ms.Target,
		Owner:    "memshell:filter",
		Metadata: map[string]any{"memshell_id": ms.ID, "webshell_id": shellID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ReleaseManagedResourceByMemshell(ms.ID, "removed"); err != nil {
		t.Fatal(err)
	}
	released, err := d.GetManagedResource(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if released.Status != ManagedReleased {
		t.Fatalf("ledger status=%s", released.Status)
	}

	ok, err := d.DeleteJavaMemshell(ms.ID)
	if err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	if _, err := d.GetJavaMemshell(ms.ID); err == nil {
		t.Fatal("record still exists after delete")
	}
}
