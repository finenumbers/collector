package store

import "testing"

func TestAuditCategory(t *testing.T) {
	if got := AuditCategory("user", "create_user"); got != "users" {
		t.Fatalf("user => %s", got)
	}
	if got := AuditCategory("device", "update_device"); got != "devices" {
		t.Fatalf("device => %s", got)
	}
	if got := AuditCategory("unknown", "user_login"); got != "auth" {
		t.Fatalf("login => %s", got)
	}
	if got := AuditCategory("widget", "frobnicate"); got != "other" {
		t.Fatalf("other => %s", got)
	}
}
