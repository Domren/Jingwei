package db

import (
	"fmt"
	"testing"
	"time"
)

func TestManagedResourceLifecycle(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	endpoint := fmt.Sprintf("127.0.0.1:%d", 20000+time.Now().UnixNano()%20000)
	defer d.Exec(`DELETE FROM managed_resources WHERE endpoint = $1`, endpoint)

	taskID := int64(424242)
	res, err := d.RegisterManagedResource(ManagedResourceInput{
		Kind:      ManagedKindCallback,
		Name:      "unit callback",
		Endpoint:  endpoint,
		Target:    "https://target.example.com",
		Owner:     "deep:1",
		TaskID:    &taskID,
		ExpiresAt: ptrTestTime(time.Now().Add(time.Hour)),
		Metadata:  map[string]any{"service": "jndi"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != ManagedActive || res.Metadata["service"] != "jndi" {
		t.Fatalf("unexpected resource: %+v", res)
	}

	// Re-registering the same kind+endpoint refreshes instead of duplicating.
	res2, err := d.RegisterManagedResource(ManagedResourceInput{
		Kind:     ManagedKindCallback,
		Name:     "unit callback updated",
		Endpoint: endpoint,
		Owner:    "deep:2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ID != res.ID || res2.Name != "unit callback updated" || res2.Owner != "deep:2" {
		t.Fatalf("re-register did not refresh: %+v (original %d)", res2, res.ID)
	}

	rows, total, err := d.ListManagedResources(ManagedKindCallback, ManagedActive, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total < 1 {
		t.Fatal("active resource not listed")
	}
	found := false
	for _, r := range rows {
		if r.ID == res.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("registered resource missing from list")
	}
	n, err := d.CountActiveManagedResources(ManagedKindCallback)
	if err != nil || n < 1 {
		t.Fatalf("count = %d, err=%v", n, err)
	}

	released, ok, err := d.ReleaseManagedResource(res.ID, "test release")
	if err != nil || !ok {
		t.Fatalf("release: ok=%v err=%v", ok, err)
	}
	if released.Status != ManagedReleased || released.Note != "test release" {
		t.Fatalf("released row = %+v", released)
	}
	if _, ok, err := d.ReleaseManagedResource(res.ID, ""); err != nil || ok {
		t.Fatalf("second release should report not found: ok=%v err=%v", ok, err)
	}
}

func TestManagedResourceExpiry(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	endpoint := fmt.Sprintf("127.0.0.1:%d", 40000+time.Now().UnixNano()%20000)
	defer d.Exec(`DELETE FROM managed_resources WHERE endpoint = $1`, endpoint)

	res, err := d.RegisterManagedResource(ManagedResourceInput{
		Kind:      ManagedKindTunnel,
		Endpoint:  endpoint,
		Owner:     "test",
		ExpiresAt: ptrTestTime(time.Now().Add(-time.Minute)),
	})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := d.ExpireManagedResources(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range expired {
		if r.ID == res.ID {
			found = true
			if r.Status != ManagedExpired {
				t.Fatalf("status = %q", r.Status)
			}
		}
	}
	if !found {
		t.Fatal("overdue resource was not expired")
	}
}

func TestReleaseManagedResourceByWebshell(t *testing.T) {
	d := deepTestSetup(t)
	t.Cleanup(func() { _ = d.Close() })

	endpoint := fmt.Sprintf("https://shell.example.com/%d.php", time.Now().UnixNano())
	defer d.Exec(`DELETE FROM managed_resources WHERE endpoint = $1`, endpoint)

	res, err := d.RegisterManagedResource(ManagedResourceInput{
		Kind:     ManagedKindWebshell,
		Endpoint: endpoint,
		Metadata: map[string]any{"webshell_id": float64(987654)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ReleaseManagedResourceByWebshell(987654, "deleted"); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetManagedResource(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ManagedReleased {
		t.Fatalf("status = %q", got.Status)
	}
}

func ptrTestTime(t time.Time) *time.Time { return &t }
