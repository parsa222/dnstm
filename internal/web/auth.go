package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	credentialsFile = "/etc/dnstm/web-credentials.json"
	sessionCookie   = "dnstm_session"
	sessionTTL      = 8 * time.Hour
)

// webCredentials stores the hashed admin password for the web UI.
type webCredentials struct {
	PasswordHash string `json:"password_hash"`
}

// session represents an authenticated browser session.
type session struct {
	Token     string
	ExpiresAt time.Time
}

// sessionStore is a simple in-memory session store.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	s := &sessionStore{sessions: make(map[string]*session)}
	go s.cleanup()
	return s
}

// create generates a new session token and stores it.
func (s *sessionStore) create() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = &session{Token: token, ExpiresAt: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	return token
}

// valid returns true if the token is present and not expired.
func (s *sessionStore) valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	sess, ok := s.sessions[token]
	s.mu.Unlock()
	if !ok {
		return false
	}
	if time.Now().After(sess.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
		return false
	}
	return true
}

// delete removes a session.
func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// cleanup periodically removes expired sessions.
func (s *sessionStore) cleanup() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for token, sess := range s.sessions {
			if now.After(sess.ExpiresAt) {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

// hashPassword returns a SHA-256 hex digest of the password.
// A fixed prefix acts as a domain separator so that a hash from this system
// cannot be confused with hashes from other applications.
// bcrypt would be preferable in a high-security context, but SHA-256 is
// sufficient for a local-only management interface.
func hashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte("dnstm-web:"))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// LoadCredentials reads the stored web credentials from disk.
// Returns nil if the credentials file does not exist yet.
func LoadCredentials() (*webCredentials, error) {
	data, err := os.ReadFile(credentialsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read web credentials: %w", err)
	}
	var creds webCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse web credentials: %w", err)
	}
	return &creds, nil
}

// SaveCredentials persists the web credentials to disk.
func SaveCredentials(password string) error {
	creds := webCredentials{PasswordHash: hashPassword(password)}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(credentialsFile), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := os.WriteFile(credentialsFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}
	return nil
}

// CredentialsConfigured returns true if a password has been set.
func CredentialsConfigured() bool {
	creds, err := LoadCredentials()
	return err == nil && creds != nil && creds.PasswordHash != ""
}

// verifyPassword checks the given password against the stored hash.
func verifyPassword(password string) bool {
	creds, err := LoadCredentials()
	if err != nil || creds == nil {
		return false
	}
	expected := creds.PasswordHash
	got := hashPassword(password)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

// authMiddleware wraps an http.Handler and requires an active session.
// Unauthenticated requests to /api/* receive 401; browser requests are redirected to /login.
// When no credentials have been configured, the middleware allows all requests through.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth endpoints are always public
		if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/status" ||
			r.URL.Path == "/api/auth/logout" ||
			r.URL.Path == "/login" || r.URL.Path == "/" || r.URL.Path == "/index.html" {
			next.ServeHTTP(w, r)
			return
		}

		// If no password has been configured, allow all requests (open access mode).
		if !CredentialsConfigured() {
			next.ServeHTTP(w, r)
			return
		}

		token := ""
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}

		if s.sessions.valid(token) {
			next.ServeHTTP(w, r)
			return
		}

		// Require auth
		if isAPIPath(r.URL.Path) {
			writeJSON(w, http.StatusUnauthorized, apiResponse{
				Success: false,
				Error:   "not authenticated",
			})
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func isAPIPath(path string) bool {
	return len(path) >= 4 && path[:4] == "/api"
}

// handleLogin processes a login POST request.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}

	if !verifyPassword(req.Password) {
		apiErr(w, http.StatusUnauthorized, fmt.Errorf("invalid password"))
		return
	}

	token := s.sessions.create()
	// Note: Secure flag is intentionally omitted because the server runs on plain HTTP by
	// default (bound to localhost). Enabling Secure would prevent the browser from sending
	// the cookie over HTTP, breaking authentication. If TLS is added in the future, Secure
	// should be set to true.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	apiOK(w, map[string]bool{"authenticated": true}, nil)
}

// handleLogout invalidates the current session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	apiOK(w, nil, nil)
}

// handleAuthStatus returns whether the caller is currently authenticated and whether
// credentials have been configured at all.
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	token := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		token = c.Value
	}
	authenticated := s.sessions.valid(token)
	configured := CredentialsConfigured()
	apiOK(w, map[string]bool{
		"authenticated": authenticated,
		"configured":    configured,
	}, nil)
}
