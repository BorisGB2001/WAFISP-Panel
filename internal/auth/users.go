// Package auth keeps panel users, signed sessions and login throttling.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"
	"wafisp/internal/i18n"

	"golang.org/x/crypto/bcrypt"
)

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"

	minPassword = 10
)

var (
	ErrBadLogin   = i18n.Errorf("Wrong username or password")
	ErrUserExists = i18n.Errorf("The user already exists")
	ErrNoUser     = i18n.Errorf("User not found")
	ErrLastAdmin  = i18n.Errorf("The last administrator cannot be deleted or demoted")

	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

	// dummyHash keeps login time the same for unknown users.
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)
)

type User struct {
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Hash      []byte    `json:"hash"`
	Created   time.Time `json:"created"`
	LastLogin time.Time `json:"last_login,omitempty"`
	// Version changes with the password and invalidates old sessions.
	Version int `json:"version"`
}

type Users struct {
	path  string
	mu    sync.Mutex
	users map[string]*User
	// mtime of the file as last read or written; a newer file (changed by
	// "wafisp -reset-password") is read again before the next use.
	mtime time.Time
}

func OpenUsers(path string) (*Users, error) {
	u := &Users{path: path, users: map[string]*User{}}
	if err := u.load(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *Users) load() error {
	fi, err := os.Stat(u.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	b, err := os.ReadFile(u.path)
	if err != nil {
		return err
	}
	var list []*User
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("%s: %w", u.path, err)
	}
	u.users = map[string]*User{}
	for _, x := range list {
		u.users[x.Name] = x
	}
	u.mtime = fi.ModTime()
	return nil
}

// refreshLocked reloads the file when someone else changed it.
func (u *Users) refreshLocked() {
	if fi, err := os.Stat(u.path); err == nil && fi.ModTime().After(u.mtime) {
		u.load()
	}
}

// Bootstrap creates an "admin" with a random password when there are no
// users and writes the password to file (0600), so the first login needs
// shell access to the server.
func (u *Users) Bootstrap(file string) (bool, error) {
	u.mu.Lock()
	empty := len(u.users) == 0
	u.mu.Unlock()
	if !empty {
		return false, nil
	}
	pw := RandomPassword()
	if err := u.Add("admin", pw, RoleAdmin); err != nil {
		return false, err
	}
	return true, os.WriteFile(file, []byte(pw+"\n"), 0o600)
}

func RandomPassword() string {
	b := make([]byte, 15)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func ValidName(name string) bool { return nameRe.MatchString(name) }

func validRole(role string) bool { return role == RoleAdmin || role == RoleViewer }

func checkPassword(pw string) error {
	if len([]rune(pw)) < minPassword {
		return i18n.Errorf("The password is shorter than %d characters", minPassword)
	}
	return nil
}

func (u *Users) Authenticate(name, pw string) (*User, error) {
	u.mu.Lock()
	u.refreshLocked()
	x := u.users[name]
	u.mu.Unlock()
	if x == nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
		return nil, ErrBadLogin
	}
	if bcrypt.CompareHashAndPassword(x.Hash, []byte(pw)) != nil {
		return nil, ErrBadLogin
	}
	u.mu.Lock()
	x.LastLogin = time.Now()
	err := u.saveLocked()
	c := *x
	u.mu.Unlock()
	return &c, err
}

func (u *Users) Get(name string) (User, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshLocked()
	x, ok := u.users[name]
	if !ok {
		return User{}, false
	}
	return *x, true
}

func (u *Users) List() []User {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshLocked()
	out := make([]User, 0, len(u.users))
	for _, x := range u.users {
		out = append(out, *x)
	}
	slices.SortFunc(out, func(a, b User) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	})
	return out
}

func (u *Users) Add(name, pw, role string) error {
	if !ValidName(name) {
		return i18n.Errorf("Username: 2–32 characters, lowercase Latin letters, digits, . _ -")
	}
	if !validRole(role) {
		return i18n.Errorf("Unknown role")
	}
	if err := checkPassword(pw); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshLocked()
	if _, ok := u.users[name]; ok {
		return ErrUserExists
	}
	u.users[name] = &User{Name: name, Role: role, Hash: h, Created: time.Now(), Version: 1}
	return u.saveLocked()
}

func (u *Users) SetPassword(name, pw string) error {
	if err := checkPassword(pw); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshLocked()
	x := u.users[name]
	if x == nil {
		return ErrNoUser
	}
	x.Hash = h
	x.Version++
	return u.saveLocked()
}

func (u *Users) SetRole(name, role string) error {
	if !validRole(role) {
		return i18n.Errorf("Unknown role")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshLocked()
	x := u.users[name]
	if x == nil {
		return ErrNoUser
	}
	if x.Role == RoleAdmin && role != RoleAdmin && u.adminsLocked() == 1 {
		return ErrLastAdmin
	}
	x.Role = role
	x.Version++
	return u.saveLocked()
}

func (u *Users) Delete(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshLocked()
	x := u.users[name]
	if x == nil {
		return ErrNoUser
	}
	if x.Role == RoleAdmin && u.adminsLocked() == 1 {
		return ErrLastAdmin
	}
	delete(u.users, name)
	return u.saveLocked()
}

func (u *Users) adminsLocked() int {
	n := 0
	for _, x := range u.users {
		if x.Role == RoleAdmin {
			n++
		}
	}
	return n
}

func (u *Users) saveLocked() error {
	list := make([]*User, 0, len(u.users))
	for _, x := range u.users {
		list = append(list, x)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(u.path, b, 0o600); err != nil {
		return err
	}
	if fi, err := os.Stat(u.path); err == nil {
		u.mtime = fi.ModTime()
	}
	return nil
}

// WriteFileAtomic writes through a temporary file in the same directory.
func WriteFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
