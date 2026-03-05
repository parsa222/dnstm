package web

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// SSHUser represents an SSH tunnel user with live connection statistics.
type SSHUser struct {
	Username    string `json:"username"`
	UID         int    `json:"uid"`
	Connections int    `json:"connections"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
}

// GetSSHUsers returns a list of SSH tunnel users (UID >= 1000, non-nobody)
// together with their current connection count gathered from active SSH sessions.
func GetSSHUsers() ([]SSHUser, error) {
	// Enumerate regular system users from /etc/passwd
	users, err := parsePasswd()
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}

	// Count active SSH sessions per user using `who` or `w`
	sessionCounts, err := countSSHSessions()
	if err != nil {
		// Not fatal – show users without session counts
		sessionCounts = make(map[string]int)
	}

	// Build result
	result := make([]SSHUser, 0, len(users))
	for _, u := range users {
		result = append(result, SSHUser{
			Username:    u.name,
			UID:         u.uid,
			Connections: sessionCounts[u.name],
		})
	}
	return result, nil
}

// AddSSHUser creates a new system user for SSH tunneling.
// The user is given a locked password; access is controlled by authorized_keys.
func AddSSHUser(username, password string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if strings.ContainsAny(username, " \t:/\\") {
		return fmt.Errorf("invalid characters in username")
	}

	// Check if user already exists
	if _, err := exec.LookPath("id"); err == nil {
		if out, _ := exec.Command("id", username).CombinedOutput(); len(out) > 0 && !strings.HasPrefix(string(out), "id:") {
			return fmt.Errorf("user '%s' already exists", username)
		}
	}

	// Create the user
	args := []string{
		"--create-home",
		"--shell", "/bin/bash",
		username,
	}
	if out, err := exec.Command("useradd", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create user: %s", strings.TrimSpace(string(out)))
	}

	// Set password if provided
	if password != "" {
		if err := setUserPassword(username, password); err != nil {
			return fmt.Errorf("failed to set password: %w", err)
		}
	}

	return nil
}

// RemoveSSHUser removes a system user and their home directory.
func RemoveSSHUser(username string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	// Safety: reject system usernames
	u, err := lookupPasswd(username)
	if err != nil {
		return fmt.Errorf("user '%s' not found", username)
	}
	if u.uid < 1000 {
		return fmt.Errorf("cannot remove system user '%s'", username)
	}

	if out, err := exec.Command("userdel", "--remove", username).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove user: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SetSSHUserPassword updates the password for an SSH tunnel user.
func SetSSHUserPassword(username, password string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	u, err := lookupPasswd(username)
	if err != nil {
		return fmt.Errorf("user '%s' not found", username)
	}
	if u.uid < 1000 {
		return fmt.Errorf("cannot modify system user '%s'", username)
	}
	return setUserPassword(username, password)
}

// --- internal helpers ---

type passwdEntry struct {
	name string
	uid  int
}

// parsePasswd reads /etc/passwd and returns entries with UID >= 1000 (excluding nobody at 65534).
func parsePasswd() ([]passwdEntry, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []passwdEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 4 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		// Only regular (non-system) users
		if uid < 1000 || uid == 65534 {
			continue
		}
		entries = append(entries, passwdEntry{name: parts[0], uid: uid})
	}
	return entries, scanner.Err()
}

// lookupPasswd returns the passwd entry for a given username.
// It searches all users (including system users) by exact name match.
func lookupPasswd(username string) (*passwdEntry, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 4 {
			continue
		}
		if parts[0] != username {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		return &passwdEntry{name: parts[0], uid: uid}, nil
	}
	return nil, fmt.Errorf("user not found")
}

// countSSHSessions uses the `who` command to count logged-in sessions per username.
func countSSHSessions() (map[string]int, error) {
	out, err := exec.Command("who").Output()
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		username := fields[0]
		// Only count pts/* (pseudo-terminal slave) sessions — these are SSH sessions on Linux.
		// Physical console ttys (tty1-6) are excluded.
		tty := fields[1]
		if strings.HasPrefix(tty, "pts/") {
			counts[username]++
		}
	}
	return counts, nil
}

// setUserPassword uses chpasswd to set a user password.
func setUserPassword(username, password string) error {
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s\n", username, password))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}
