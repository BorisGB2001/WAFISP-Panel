package auth

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUsersLifecycle(t *testing.T) {
	dir := t.TempDir()
	u, err := OpenUsers(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := u.Bootstrap(filepath.Join(dir, "pw"))
	if err != nil || !created {
		t.Fatalf("bootstrap: %v %v", created, err)
	}
	if err := u.Add("bob", "short", RoleViewer); err == nil {
		t.Fatal("short password accepted")
	}
	if err := u.Add("Bob!", "long-enough-pw", RoleViewer); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := u.Add("bob", "long-enough-pw", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Authenticate("bob", "wrong-password"); err != ErrBadLogin {
		t.Fatal("wrong password accepted")
	}
	if _, err := u.Authenticate("nobody", "whatever-pw"); err != ErrBadLogin {
		t.Fatal("unknown user accepted")
	}
	if x, err := u.Authenticate("bob", "long-enough-pw"); err != nil || x.Role != RoleViewer {
		t.Fatalf("login: %v", err)
	}
	if err := u.Delete("admin"); err != ErrLastAdmin {
		t.Fatalf("last admin deleted: %v", err)
	}
	if err := u.SetRole("admin", RoleViewer); err != ErrLastAdmin {
		t.Fatalf("last admin demoted: %v", err)
	}

	// Reopen from disk.
	u2, err := OpenUsers(filepath.Join(dir, "users.json"))
	if err != nil || len(u2.List()) != 2 {
		t.Fatalf("reload: %v %d", err, len(u2.List()))
	}
}

func TestSessions(t *testing.T) {
	s, err := OpenSessions(filepath.Join(t.TempDir(), "key"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cookie, sess := s.New(User{Name: "bob", Version: 3})
	got, ok := s.Parse(cookie)
	if !ok || got.User != "bob" || got.Version != 3 {
		t.Fatalf("parse: %+v %v", got, ok)
	}
	if _, ok := s.Parse(strings.Replace(cookie, ".", "x.", 1)); ok {
		t.Fatal("tampered cookie accepted")
	}
	_, other := s.New(User{Name: "bob", Version: 3})
	if s.CSRF(sess) == s.CSRF(other) {
		t.Fatal("CSRF token not unique per session")
	}
}

func TestThrottle(t *testing.T) {
	th := NewThrottle(3, time.Minute)
	for i := 0; i < 3; i++ {
		th.Fail("ip:1", "user:bob")
	}
	if !th.Blocked("user:bob") {
		t.Fatal("not blocked after 3 failures")
	}
	th.Reset("user:bob")
	if th.Blocked("user:bob") || !th.Blocked("ip:1") {
		t.Fatal("reset touched the wrong key")
	}
}
