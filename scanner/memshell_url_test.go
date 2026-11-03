package scanner

import (
	"reflect"
	"testing"
)

func TestMemshellURLsFor(t *testing.T) {
	cases := []struct {
		name      string
		parentURL string
		shellPath string
		port      int
		want      []string
	}{
		{
			name:      "war context before root",
			parentURL: "http://127.0.0.1:8081/lab/upload/jwk.jsp",
			shellPath: "/jwm",
			want:      []string{"http://127.0.0.1:8081/lab/jwm", "http://127.0.0.1:8081/lab/upload/jwm", "http://127.0.0.1:8081/jwm"},
		},
		{
			name:      "root context shell has one candidate",
			parentURL: "http://10.0.0.5:8080/shell.jsp",
			shellPath: "/jwm",
			want:      []string{"http://10.0.0.5:8080/jwm"},
		},
		{
			name:      "agent listens on its own port",
			parentURL: "http://10.0.0.5:8080/lab/shell.jsp",
			shellPath: "/jwm",
			port:      41000,
			want:      []string{"http://10.0.0.5:41000/jwm"},
		},
	}
	for _, c := range cases {
		got, err := MemshellURLsFor(c.parentURL, c.shellPath, c.port)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if _, err := MemshellURLsFor("://bad", "/jwm", 0); err == nil {
		t.Error("无效的父壳地址应报错")
	}
}
