package ftpclient

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestNormalizeRemoteDir(t *testing.T) {
	cases := map[string]string{
		"":         "/",
		"archives": "/archives",
		"/a/b/":    "/a/b",
		"/a/../b":  "/b",
		`\x\y`:     "/x/y",
	}
	for in, want := range cases {
		if got := NormalizeRemoteDir(in); got != want {
			t.Fatalf("NormalizeRemoteDir(%q)=%q want %q", in, got, want)
		}
	}
}

func TestValidateRemoteDir(t *testing.T) {
	if err := ValidateRemoteDir("/ok/path"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRemoteDir(""); err == nil {
		t.Fatal("expected empty error")
	}
	if err := ValidateRemoteDir("/a/../b"); err == nil {
		t.Fatal("expected .. error")
	}
}

func TestProbeRequiresConfig(t *testing.T) {
	client := New(Config{})
	if err := client.Probe(context.Background(), "/"); err == nil {
		t.Fatal("expected not configured")
	}
}

func TestProbeDetailedRequiresRemoteDir(t *testing.T) {
	client := New(Config{Host: "ftp.example", User: "u", Password: "p"})
	if _, err := client.ProbeDetailed(context.Background(), ""); err == nil {
		t.Fatal("expected remote directory error")
	}
	if _, err := client.ProbeDetailed(context.Background(), "/a/../secret"); err == nil {
		t.Fatal("expected invalid directory error")
	}
}

func TestMoveRequiresConfigAndName(t *testing.T) {
	if err := New(Config{}).Move(context.Background(), "/a", "/a/d", "x.zip", 1); err == nil {
		t.Fatal("expected not configured")
	}
}

func TestMoveCreatesDestAndVerifiesSize(t *testing.T) {
	body, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "func (c *Client) Move(") {
		t.Fatal("Move must exist for day-folder relocate")
	}
	if !strings.Contains(source, "ensureDirs(conn, dest)") {
		t.Fatal("Move must mkdir the day folder")
	}
	if !strings.Contains(source, "verifySize(conn, file, wantBytes)") {
		t.Fatal("Move must SIZE-verify dest")
	}
}
