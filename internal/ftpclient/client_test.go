package ftpclient

import (
	"context"
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
