package dashboard

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"
)

// UsersFile is the file in the state directory that holds the users.
const UsersFile = "users.json"

// passwordIterations is the PBKDF2-HMAC-SHA256 work factor that the OWASP
// Password Storage Cheat Sheet recommends. Each user's count is stored
// with the user, so it can be raised later without breaking old ones.
const passwordIterations = 600_000

// newIterations is the count for new passwords. Tests lower it; nothing
// else changes it.
var newIterations = passwordIterations

// storedUser is one user as written to the file. Only a salted hash of the
// password is kept.
type storedUser struct {
	Name       string    `json:"name"`
	Salt       string    `json:"salt"`
	Key        string    `json:"key"`
	Iterations int       `json:"iterations"`
	Created    time.Time `json:"created"`
}

type usersFile struct {
	Users []storedUser `json:"users"`
}

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// users reads and changes the users file. The running dashboard reads the
// file again when it changes, so a user added or removed with the command
// counts without a restart.
type users struct {
	path string

	mu      sync.Mutex
	list    []storedUser
	modTime time.Time
	size    int64
}

func openUsers(stateDir string) (*users, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	u := &users{path: filepath.Join(stateDir, UsersFile)}
	if err := u.reload(); err != nil {
		return nil, err
	}
	return u, nil
}

// reload reads the file when it changed since the last read.
func (u *users) reload() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, err := u.reloadLocked()
	return err
}

// reloadLocked is reload with u.mu held. It reports whether the list
// changed.
func (u *users) reloadLocked() (bool, error) {
	info, err := os.Stat(u.path)
	if errors.Is(err, os.ErrNotExist) {
		changed := len(u.list) > 0
		u.list, u.modTime, u.size = nil, time.Time{}, 0
		return changed, nil
	}
	if err != nil {
		return false, err
	}
	if info.ModTime().Equal(u.modTime) && info.Size() == u.size {
		return false, nil
	}
	data, err := os.ReadFile(u.path)
	if err != nil {
		return false, err
	}
	var f usersFile
	if err := json.Unmarshal(data, &f); err != nil {
		return false, fmt.Errorf("%s: %w", u.path, err)
	}
	u.list, u.modTime, u.size = f.Users, info.ModTime(), info.Size()
	return true, nil
}

// names returns the names of the users.
func (u *users) names() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reloadLocked()
	var names []string
	for _, su := range u.list {
		names = append(names, su.Name)
	}
	return names
}

// stamp identifies a user's current password: its salt, which changes
// with each new password. It is "" when the user does not exist. A session
// keeps the stamp of its login, so a new password or a removed user ends
// the session.
func (u *users) stamp(name string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reloadLocked()
	for _, su := range u.list {
		if su.Name == name {
			return su.Salt
		}
	}
	return ""
}

// add creates a user with a new random password and returns the password.
// It is shown once and not stored anywhere.
func (u *users) add(name string) (string, error) {
	if !validName.MatchString(name) {
		return "", fmt.Errorf("user name %q: use 1 to 64 letters, digits, '.', '_' or '-'", name)
	}
	return u.change(name, func(list []storedUser, i int, su storedUser) ([]storedUser, error) {
		if i >= 0 {
			return nil, fmt.Errorf("user %q already exists", name)
		}
		return append(list, su), nil
	})
}

// reset gives an existing user a new random password and returns it.
func (u *users) reset(name string) (string, error) {
	return u.change(name, func(list []storedUser, i int, su storedUser) ([]storedUser, error) {
		if i < 0 {
			return nil, fmt.Errorf("there is no user %q", name)
		}
		list[i] = su
		return list, nil
	})
}

// remove deletes a user. Its logins end at its next request.
func (u *users) remove(name string) error {
	_, err := u.change(name, func(list []storedUser, i int, _ storedUser) ([]storedUser, error) {
		if i < 0 {
			return nil, fmt.Errorf("there is no user %q", name)
		}
		return slices.Delete(list, i, i+1), nil
	})
	return err
}

// change makes a new password for name, lets edit change the list, and
// writes the file.
func (u *users) change(name string, edit func(list []storedUser, i int, su storedUser) ([]storedUser, error)) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, err := u.reloadLocked(); err != nil {
		return "", err
	}
	password := rand.Text()
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := derive(password, salt, newIterations)
	if err != nil {
		return "", err
	}
	su := storedUser{Name: name, Salt: hex.EncodeToString(salt), Key: hex.EncodeToString(key), Iterations: newIterations, Created: time.Now().UTC()}
	i := slices.IndexFunc(u.list, func(s storedUser) bool { return s.Name == name })
	list, err := edit(slices.Clone(u.list), i, su)
	if err != nil {
		return "", err
	}
	if err := u.write(list); err != nil {
		return "", err
	}
	return password, nil
}

// write replaces the file whole, so that a reader never sees half of it.
func (u *users) write(list []storedUser) error {
	data, err := json.MarshalIndent(usersFile{Users: list}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(u.path), ".users-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// CreateTemp makes the file readable by its owner only (0600).
	if err := os.Rename(tmp.Name(), u.path); err != nil {
		return err
	}
	u.list = list
	u.modTime, u.size = time.Time{}, 0
	return nil
}

// dummySalt is used for a user name that does not exist, so that a wrong
// name takes as long to check as a wrong password and does not tell which
// names exist.
var dummySalt = make([]byte, 16)

// check reports whether password is the password of the user name, and
// returns the stamp of that password.
func (u *users) check(name, password string) (stamp string, ok bool) {
	u.mu.Lock()
	u.reloadLocked()
	i := slices.IndexFunc(u.list, func(s storedUser) bool { return s.Name == name })
	var su storedUser
	if i >= 0 {
		su = u.list[i]
	}
	u.mu.Unlock()

	salt, err1 := hex.DecodeString(su.Salt)
	want, err2 := hex.DecodeString(su.Key)
	iterations := su.Iterations
	if i < 0 || err1 != nil || err2 != nil || iterations < 1 {
		salt, want, iterations = dummySalt, make([]byte, 32), newIterations
	}
	got, err := derive(password, salt, iterations)
	if err != nil {
		return "", false
	}
	if subtle.ConstantTimeCompare(got, want) != 1 || i < 0 {
		return "", false
	}
	return su.Salt, true
}

func derive(password string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iterations, 32)
}

// AddUser adds a user to the users file in stateDir and returns the
// user's new password, which is shown once.
func AddUser(stateDir, name string) (string, error) {
	u, err := openUsers(stateDir)
	if err != nil {
		return "", err
	}
	return u.add(name)
}

// ResetPassword gives a user a new password and returns it. A running
// dashboard ends the user's logins at their next request.
func ResetPassword(stateDir, name string) (string, error) {
	u, err := openUsers(stateDir)
	if err != nil {
		return "", err
	}
	return u.reset(name)
}

// RemoveUser removes a user. A running dashboard ends the user's logins at
// their next request.
func RemoveUser(stateDir, name string) error {
	u, err := openUsers(stateDir)
	if err != nil {
		return err
	}
	return u.remove(name)
}
