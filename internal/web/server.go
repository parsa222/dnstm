package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/net2share/dnstm/internal/actions"
	"github.com/net2share/dnstm/internal/config"
	"github.com/net2share/dnstm/internal/dnsrouter"
	"github.com/net2share/dnstm/internal/handlers"
	"github.com/net2share/dnstm/internal/router"
)

// Server is the dnstm web GUI server.
type Server struct {
	addr     string
	sessions *sessionStore
}

// New creates a new web server bound to the given address.
func New(addr string) *Server {
	return &Server{
		addr:     addr,
		sessions: newSessionStore(),
	}
}

// Run starts the HTTP server and blocks until it stops.
func (s *Server) Run() error {
	mux := http.NewServeMux()

	// Static files & login page
	mux.HandleFunc("/", handleIndex)

	// Auth endpoints (public)
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)

	// Status
	mux.HandleFunc("GET /api/status", s.handleStatus)

	// Tunnels
	mux.HandleFunc("GET /api/tunnels", s.handleTunnelList)
	mux.HandleFunc("POST /api/tunnels", s.handleTunnelAdd)
	mux.HandleFunc("DELETE /api/tunnels/{tag}", s.handleTunnelRemove)
	mux.HandleFunc("POST /api/tunnels/{tag}/start", s.handleTunnelStart)
	mux.HandleFunc("POST /api/tunnels/{tag}/stop", s.handleTunnelStop)
	mux.HandleFunc("POST /api/tunnels/{tag}/restart", s.handleTunnelRestart)
	mux.HandleFunc("GET /api/tunnels/{tag}/logs", s.handleTunnelLogs)
	mux.HandleFunc("GET /api/tunnels/{tag}/share", s.handleTunnelShare)

	// Backends
	mux.HandleFunc("GET /api/backends", s.handleBackendList)
	mux.HandleFunc("POST /api/backends", s.handleBackendAdd)
	mux.HandleFunc("DELETE /api/backends/{tag}", s.handleBackendRemove)

	// Router
	mux.HandleFunc("GET /api/router/logs", s.handleRouterLogs)
	mux.HandleFunc("POST /api/router/start", s.handleRouterStart)
	mux.HandleFunc("POST /api/router/stop", s.handleRouterStop)
	mux.HandleFunc("POST /api/router/restart", s.handleRouterRestart)
	mux.HandleFunc("POST /api/router/mode", s.handleRouterMode)
	mux.HandleFunc("POST /api/router/switch", s.handleRouterSwitch)

	// SSH Users (management section)
	mux.HandleFunc("GET /api/ssh-users", s.handleSSHUserList)
	mux.HandleFunc("POST /api/ssh-users", s.handleSSHUserAdd)
	mux.HandleFunc("DELETE /api/ssh-users/{username}", s.handleSSHUserRemove)
	mux.HandleFunc("PUT /api/ssh-users/{username}/password", s.handleSSHUserSetPassword)

	handler := s.authMiddleware(mux)

	if !CredentialsConfigured() {
		fmt.Println("⚠️  Web UI password not set. Run: sudo dnstm web --set-password <password>")
		fmt.Println("   Until a password is set, the web UI is accessible without authentication.")
	}

	fmt.Printf("Web GUI listening on http://%s\n", s.addr)
	return http.ListenAndServe(s.addr, handler)
}

// --- helpers ---

type apiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Output  []string    `json:"output,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiOK(w http.ResponseWriter, data interface{}, output []string) {
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: data, Output: output})
}

func apiErr(w http.ResponseWriter, status int, err error, output ...[]string) {
	resp := apiResponse{Success: false, Error: err.Error()}
	if len(output) > 0 {
		resp.Output = output[0]
	}
	writeJSON(w, status, resp)
}

// newCtx builds an actions.Context for non-interactive (web) use.
func newCtx(values map[string]interface{}) *actions.Context {
	if values == nil {
		values = make(map[string]interface{})
	}
	ctx := &actions.Context{
		Ctx:           context.Background(),
		Values:        values,
		Output:        NewBufferedOutput(),
		IsInteractive: false,
	}
	if router.IsInitialized() {
		if cfg, err := config.Load(); err == nil {
			ctx.Config = cfg
		}
	}
	return ctx
}

func outputLines(ctx *actions.Context) []string {
	if bo, ok := ctx.Output.(*BufferedOutput); ok {
		return bo.Lines()
	}
	return nil
}

// decode reads JSON body into v.
func decode(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// --- static ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

// --- status ---

type tunnelStatusDTO struct {
	Tag       string `json:"tag"`
	Transport string `json:"transport"`
	Backend   string `json:"backend"`
	Domain    string `json:"domain"`
	Port      int    `json:"port"`
	Running   bool   `json:"running"`
	Installed bool   `json:"installed"`
	IsActive  bool   `json:"is_active"`
	IsDefault bool   `json:"is_default"`
}

type backendDTO struct {
	Tag     string `json:"tag"`
	Type    string `json:"type"`
	Address string `json:"address,omitempty"`
}

type routerDTO struct {
	Running   bool `json:"running"`
	Installed bool `json:"installed"`
}

type statusDTO struct {
	Initialized bool              `json:"initialized"`
	Mode        string            `json:"mode"`
	Active      string            `json:"active,omitempty"`
	Default     string            `json:"default,omitempty"`
	Tunnels     []tunnelStatusDTO `json:"tunnels"`
	Backends    []backendDTO      `json:"backends"`
	Router      routerDTO         `json:"router"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !router.IsInitialized() {
		apiOK(w, statusDTO{Initialized: false}, nil)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		apiErr(w, http.StatusInternalServerError, err)
		return
	}

	dto := statusDTO{
		Initialized: true,
		Mode:        cfg.Route.Mode,
		Active:      cfg.Route.Active,
		Default:     cfg.Route.Default,
	}

	for _, t := range cfg.Tunnels {
		tunnel := router.NewTunnel(&t)
		dto.Tunnels = append(dto.Tunnels, tunnelStatusDTO{
			Tag:       t.Tag,
			Transport: string(t.Transport),
			Backend:   t.Backend,
			Domain:    t.Domain,
			Port:      t.Port,
			Running:   tunnel.IsActive(),
			Installed: tunnel.IsInstalled(),
			IsActive:  cfg.Route.Active == t.Tag,
			IsDefault: cfg.Route.Default == t.Tag,
		})
	}

	for _, b := range cfg.Backends {
		dto.Backends = append(dto.Backends, backendDTO{
			Tag:     b.Tag,
			Type:    string(b.Type),
			Address: b.Address,
		})
	}

	svc := dnsrouter.NewService()
	dto.Router = routerDTO{
		Running:   svc.IsActive(),
		Installed: svc.IsServiceInstalled(),
	}

	apiOK(w, dto, nil)
}

// --- tunnels ---

func (s *Server) handleTunnelList(w http.ResponseWriter, r *http.Request) {
	s.handleStatus(w, r)
}

func (s *Server) handleTunnelAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transport string `json:"transport"`
		Backend   string `json:"backend"`
		Domain    string `json:"domain"`
		Tag       string `json:"tag"`
		Port      int    `json:"port"`
		MTU       int    `json:"mtu"`
	}
	if err := decode(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}

	values := map[string]interface{}{
		"transport": req.Transport,
		"backend":   req.Backend,
		"domain":    req.Domain,
		"tag":       req.Tag,
		"port":      req.Port,
		"mtu":       req.MTU,
	}
	ctx := newCtx(values)

	if err := handlers.HandleTunnelAdd(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err, outputLines(ctx))
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleTunnelRemove(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	ctx := newCtx(map[string]interface{}{"tag": tag})
	if err := handlers.HandleTunnelRemove(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleTunnelStart(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	ctx := newCtx(map[string]interface{}{"tag": tag})
	if err := handlers.HandleTunnelStart(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleTunnelStop(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	ctx := newCtx(map[string]interface{}{"tag": tag})
	if err := handlers.HandleTunnelStop(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleTunnelRestart(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	ctx := newCtx(map[string]interface{}{"tag": tag})
	if err := handlers.HandleTunnelRestart(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleTunnelLogs(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	lines := 100
	ctx := newCtx(map[string]interface{}{"tag": tag, "lines": lines})
	if err := handlers.HandleTunnelLogs(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	// The logs are written to output as a single big string; join and return
	out := outputLines(ctx)
	apiOK(w, strings.Join(out, "\n"), nil)
}

func (s *Server) handleTunnelShare(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	ctx := newCtx(map[string]interface{}{"tag": tag})
	if err := handlers.HandleTunnelShare(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	out := outputLines(ctx)
	url := ""
	if len(out) > 0 {
		url = strings.TrimSpace(out[0])
	}
	apiOK(w, url, out)
}

// --- backends ---

func (s *Server) handleBackendList(w http.ResponseWriter, r *http.Request) {
	if !router.IsInitialized() {
		apiOK(w, []backendDTO{}, nil)
		return
	}
	cfg, err := config.Load()
	if err != nil {
		apiErr(w, http.StatusInternalServerError, err)
		return
	}
	dtos := make([]backendDTO, 0, len(cfg.Backends))
	for _, b := range cfg.Backends {
		dtos = append(dtos, backendDTO{
			Tag:     b.Tag,
			Type:    string(b.Type),
			Address: b.Address,
		})
	}
	apiOK(w, dtos, nil)
}

func (s *Server) handleBackendAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag      string `json:"tag"`
		Type     string `json:"type"`
		Address  string `json:"address"`
		Password string `json:"password"`
		Method   string `json:"method"`
	}
	if err := decode(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	values := map[string]interface{}{
		"tag":      req.Tag,
		"type":     req.Type,
		"address":  req.Address,
		"password": req.Password,
		"method":   req.Method,
	}
	ctx := newCtx(values)
	if err := handlers.HandleBackendAdd(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleBackendRemove(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	ctx := newCtx(map[string]interface{}{"tag": tag})
	if err := handlers.HandleBackendRemove(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

// --- router ---

func (s *Server) handleRouterLogs(w http.ResponseWriter, r *http.Request) {
	ctx := newCtx(map[string]interface{}{"lines": 100})
	if err := handlers.HandleRouterLogs(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	out := outputLines(ctx)
	apiOK(w, strings.Join(out, "\n"), nil)
}

func (s *Server) handleRouterStart(w http.ResponseWriter, r *http.Request) {
	ctx := newCtx(nil)
	if err := handlers.HandleRouterStart(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleRouterStop(w http.ResponseWriter, r *http.Request) {
	ctx := newCtx(nil)
	if err := handlers.HandleRouterStop(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleRouterRestart(w http.ResponseWriter, r *http.Request) {
	// HandleRouterStart always calls r.Restart() internally, making it an idempotent
	// start-or-restart. We reuse it here for the explicit restart endpoint.
	ctx := newCtx(nil)
	if err := handlers.HandleRouterStart(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleRouterMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := decode(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	ctx := newCtx(map[string]interface{}{"mode": req.Mode})
	if err := handlers.HandleRouterMode(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

func (s *Server) handleRouterSwitch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tag string `json:"tag"`
	}
	if err := decode(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	ctx := newCtx(map[string]interface{}{"tag": req.Tag})
	if err := handlers.HandleRouterSwitch(ctx); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, outputLines(ctx))
}

// --- SSH users ---

func (s *Server) handleSSHUserList(w http.ResponseWriter, r *http.Request) {
	users, err := GetSSHUsers()
	if err != nil {
		apiErr(w, http.StatusInternalServerError, err)
		return
	}
	apiOK(w, users, nil)
}

func (s *Server) handleSSHUserAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	if err := AddSSHUser(req.Username, req.Password); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, nil)
}

func (s *Server) handleSSHUserRemove(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if err := RemoveSSHUser(username); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, nil)
}

func (s *Server) handleSSHUserSetPassword(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	if err := SetSSHUserPassword(username, req.Password); err != nil {
		apiErr(w, http.StatusBadRequest, err)
		return
	}
	apiOK(w, nil, nil)
}
