package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Both the discovery prober and the injection harvester follow a redirect only
// while it stays on the original host and within three hops. Following any
// further would turn an authorized scan of one lab host into requests aimed at
// whatever a page happens to point to.
func redirectClients(t *testing.T) map[string]*http.Client {
	t.Helper()
	return map[string]*http.Client{
		"prober":  NewProber(5 * time.Second).client,
		"harvest": newHarvestClient(5 * time.Second),
	}
}

func TestRedirectPolicyFollowsSameHostChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/mid", http.StatusFound)
		case "/mid":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			fmt.Fprint(w, "landed")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	for name, client := range redirectClients(t) {
		t.Run(name, func(t *testing.T) {
			resp, err := client.Get(srv.URL + "/start")
			if err != nil {
				t.Fatalf("request error: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || string(body) != "landed" {
				t.Fatalf("status = %d body = %q, want 200 landed", resp.StatusCode, body)
			}
		})
	}
}

func TestRedirectPolicyStopsAfterThreeHops(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/hop%d", &n); err != nil {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		http.Redirect(w, r, fmt.Sprintf("/hop%d", n+1), http.StatusFound)
	}))
	defer srv.Close()

	for name, client := range redirectClients(t) {
		t.Run(name, func(t *testing.T) {
			mu.Lock()
			hits = nil
			mu.Unlock()

			resp, err := client.Get(srv.URL + "/hop0")
			if err != nil {
				t.Fatalf("request error: %v", err)
			}
			defer resp.Body.Close()
			// The third redirect is refused, so the 302 from /hop2 is final.
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want 302 at the hop cap", resp.StatusCode)
			}

			mu.Lock()
			got := append([]string(nil), hits...)
			mu.Unlock()
			want := []string{"/hop0", "/hop1", "/hop2"}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("hops requested = %v, want %v", got, want)
			}
		})
	}
}

func TestRedirectPolicyBlocksCrossHostRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// .invalid never resolves; if the policy let the request through, the
		// client would fail with a DNS error instead of returning this 302.
		http.Redirect(w, r, "http://third-party.invalid/collect", http.StatusFound)
	}))
	defer srv.Close()

	for name, client := range redirectClients(t) {
		t.Run(name, func(t *testing.T) {
			resp, err := client.Get(srv.URL + "/go")
			if err != nil {
				t.Fatalf("request error: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want the unfollowed 302", resp.StatusCode)
			}
			if loc := resp.Header.Get("Location"); !strings.Contains(loc, "third-party.invalid") {
				t.Fatalf("location = %q, want the cross-host target", loc)
			}
		})
	}
}
