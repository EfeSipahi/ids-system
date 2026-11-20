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
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// UsersFile is the file in the state directory that holds the users.
const UsersFile = "users.json"

// usersLockFile is the lock file that every change of UsersFile takes, so
// that the running dashboard and the command-line commands, which both
// write the file, can't lose each other's change (C3 of
// docs/development-plan-marks-users.md).
const usersLockFile = "users.lock"

// errInUse is the error of a lock that another program holds.
var errInUse = errors.New("in use by another program")

// The roles (G3), a ladder: each one may do what the one before it may.
const (
	// RoleViewer reads every page and record.
	RoleViewer = "viewer"
	// RoleAnalyst also marks alerts and uses the test tab.
	RoleAnalyst = "analyst"
	// RoleAdmin also manages users and sees the change log.
	RoleAdmin = "admin"
)

// Roles lists the roles from the least to the most.
var Roles = []string{RoleViewer, RoleAnalyst, RoleAdmin}

// allows reports whether role may do what needs the role least.
func allows(role, least string) bool {
	return slices.Index(Roles, role) >= slices.Index(Roles, least) && slices.Contains(Roles, role)
}

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
	// Role is the user's role. A user written before roles existed has
	// none and is an admin (C5).
	Role string `json:"role,omitempty"`
}

// role returns the user's role, an admin when none is written.
func (su storedUser) role() string {
	if su.Role == "" {
		return RoleAdmin
	}
	return su.Role
}

// stamp identifies the user's password and role: the password's salt,
// which changes with each new password, and the role. A session keeps the
// stamp of its login, so a new password, a new role or a removed user ends
// the session (G4, C2).
func (su storedUser) stamp() string {
	return su.Salt + "/" + su.role()
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
	lock string // usersLockFile

	mu      sync.Mutex
	list    []storedUser
	modTime time.Time
	size    int64
}

func openUsers(stateDir string) (*users, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	u := &users{path: filepath.Join(stateDir, UsersFile), lock: filepath.Join(stateDir, usersLockFile)}
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

// stamp returns the stamp of a user's password and role (storedUser.stamp),
// or "" when the user does not exist.
func (u *users) stamp(name string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reloadLocked()
	for _, su := range u.list {
		if su.Name == name {
			return su.stamp()
		}
	}
	return ""
}

// role returns a user's role, or "" when the user does not exist.
func (u *users) role(name string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reloadLocked()
	for _, su := range u.list {
		if su.Name == name {
			return su.role()
		}
	}
	return ""
}

// errLastAdmin refuses a change that would leave no admin (G4).
var errLastAdmin = errors.New("this is the last admin; make another user an admin first")

// admins counts the admins of list.
func admins(list []storedUser) int {
	n := 0
	for _, su := range list {
		if su.role() == RoleAdmin {
			n++
		}
	}
	return n
}

// add creates a user with a role and a new random password, and returns
// the password. It is shown once and not stored anywhere.
func (u *users) add(name, role string) (string, error) {
	if !validName.MatchString(name) {
		return "", fmt.Errorf("user name %q: use 1 to 64 letters, digits, '.', '_' or '-'", name)
	}
	if !slices.Contains(Roles, role) {
		return "", fmt.Errorf("role %q: give viewer, analyst or admin", role)
	}
	var password string
	err := u.update(func(list []storedUser) ([]storedUser, error) {
		if slices.ContainsFunc(list, func(s storedUser) bool { return s.Name == name }) {
			return nil, fmt.Errorf("user %q already exists", name)
		}
		su, p, err := newPassword(storedUser{Name: name, Role: role, Created: time.Now().UTC()})
		password = p
		return append(list, su), err
	})
	return password, err
}

// reset gives an existing user a new random password and returns it. The
// user keeps their role.
func (u *users) reset(name string) (string, error) {
	var password string
	err := u.update(func(list []storedUser) ([]storedUser, error) {
		i := slices.IndexFunc(list, func(s storedUser) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("there is no user %q", name)
		}
		su, p, err := newPassword(list[i])
		list[i], password = su, p
		return list, err
	})
	return password, err
}

// setRole gives a user another role. The last admin can't be given a lower
// one (G4).
func (u *users) setRole(name, role string) error {
	if !slices.Contains(Roles, role) {
		return fmt.Errorf("role %q: give viewer, analyst or admin", role)
	}
	return u.update(func(list []storedUser) ([]storedUser, error) {
		i := slices.IndexFunc(list, func(s storedUser) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("there is no user %q", name)
		}
		if list[i].role() == RoleAdmin && role != RoleAdmin && admins(list) == 1 {
			return nil, errLastAdmin
		}
		list[i].Role = role
		return list, nil
	})
}

// remove deletes a user. Its logins end at its next request. The last
// admin can't be removed (G4).
func (u *users) remove(name string) error {
	return u.update(func(list []storedUser) ([]storedUser, error) {
		i := slices.IndexFunc(list, func(s storedUser) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("there is no user %q", name)
		}
		if list[i].role() == RoleAdmin && admins(list) == 1 {
			return nil, errLastAdmin
		}
		return slices.Delete(list, i, i+1), nil
	})
}

// Limits of a password a user chooses (G4): NIST SP 800-63B-4 asks for at
// least 15 characters when a password is the only factor, and forbids
// rules about mixing kinds of characters.
const (
	minChosenPassword = 15
	maxChosenPassword = 256
)

// checkChosen says what is wrong with a password a user chose, or nil.
// Length counts characters (Unicode code points), as NIST asks.
func checkChosen(password string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case !utf8.ValidString(password):
		return errors.New("the password is not valid text")
	case n < minChosenPassword:
		return fmt.Errorf("the password has %d characters; it needs at least %d", n, minChosenPassword)
	case n > maxChosenPassword:
		return fmt.Errorf("the password has %d characters; at most %d", n, maxChosenPassword)
	}
	return nil
}

// setPassword gives a user the password they chose, and returns the new
// stamp, so that the user's own session can go on (G4).
func (u *users) setPassword(name, password string) (string, error) {
	if err := checkChosen(password); err != nil {
		return "", err
	}
	var stamp string
	err := u.update(func(list []storedUser) ([]storedUser, error) {
		i := slices.IndexFunc(list, func(s storedUser) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("there is no user %q", name)
		}
		salt := make([]byte, 16)
		rand.Read(salt)
		key, err := derive(password, salt, newIterations)
		if err != nil {
			return nil, err
		}
		list[i].Salt, list[i].Key, list[i].Iterations = hex.EncodeToString(salt), hex.EncodeToString(key), newIterations
		stamp = list[i].stamp()
		return list, nil
	})
	return stamp, err
}

// userInfo is what the Users page shows of a user: never a hash or salt.
type userInfo struct {
	Name    string    `json:"name"`
	Role    string    `json:"role"`
	Created time.Time `json:"created"`
}

// infos returns the users, by name.
func (u *users) infos() []userInfo {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reloadLocked()
	out := make([]userInfo, 0, len(u.list))
	for _, su := range u.list {
		out = append(out, userInfo{Name: su.Name, Role: su.role(), Created: su.Created})
	}
	slices.SortFunc(out, func(a, b userInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// newPassword gives su a new random password and returns it.
func newPassword(su storedUser) (storedUser, string, error) {
	password := rand.Text()
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := derive(password, salt, newIterations)
	if err != nil {
		return su, "", err
	}
	su.Salt, su.Key, su.Iterations = hex.EncodeToString(salt), hex.EncodeToString(key), newIterations
	return su, password, nil
}

// update lets edit change the list of users and writes the file. It holds
// the users' lock file from reading the file to writing it, so that
// another program's change at the same time is not lost (C3).
func (u *users) update(edit func(list []storedUser) ([]storedUser, error)) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	lock, err := lockFile(u.lock, true)
	if err != nil {
		return err
	}
	defer unlockFile(lock)
	// Read the file whatever its time and size say: another program may
	// have changed it within the same clock tick.
	u.modTime, u.size = time.Time{}, 0
	if _, err := u.reloadLocked(); err != nil {
		return err
	}
	list, err := edit(slices.Clone(u.list))
	if err != nil {
		return err
	}
	for i := range list {
		list[i].Role = list[i].role()
	}
	return u.write(list)
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
	return su.stamp(), true
}

func derive(password string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iterations, 32)
}

// AddUser adds a user with a role to the users file in stateDir and
// returns the user's new password, which is shown once.
func AddUser(stateDir, name, role string) (string, error) {
	u, err := openUsers(stateDir)
	if err != nil {
		return "", err
	}
	return u.add(name, role)
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
// their next request. The last admin can't be removed.
func RemoveUser(stateDir, name string) error {
	u, err := openUsers(stateDir)
	if err != nil {
		return err
	}
	return u.remove(name)
}
