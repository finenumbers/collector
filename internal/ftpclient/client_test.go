package ftpclient

import "testing"

func TestNormalizeRemoteDir(t *testing.T) {
	cases := map[string]string{
		"":           "/",
		"archives":   "/archives",
		"/a/b/":      "/a/b",
		"/a/../b":    "/b",
		`\x\y`:       "/x/y",
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
