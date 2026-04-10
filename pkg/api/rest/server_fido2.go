//go:build fido2

package rest

import (
	"net/http"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// FIDO2Config holds the FIDO2/WebAuthn configuration exposed through the REST
// capabilities endpoint.
type FIDO2Config struct {
	Enabled          bool
	RPID             string
	RPName           string
	AllowFIDO2Only   bool
	RequireMFA       bool
	Attestation      string
	UserVerification string
}

// fido2State holds per-server FIDO2 state without modifying the Server struct.
type fido2State struct {
	manager *fido2.FIDO2AccountsManager
	config  *FIDO2Config
}

var (
	fido2States   = make(map[*Server]*fido2State)
	fido2StatesMu sync.RWMutex
)

// setFIDO2State stores FIDO2 state for the given server.
func setFIDO2State(s *Server, state *fido2State) {
	fido2StatesMu.Lock()
	fido2States[s] = state
	fido2StatesMu.Unlock()
}

// getFIDO2State retrieves the FIDO2 state for the given server. Returns nil if
// FIDO2 has not been configured on the server.
func getFIDO2State(s *Server) *fido2State {
	fido2StatesMu.RLock()
	defer fido2StatesMu.RUnlock()
	return fido2States[s]
}

// removeFIDO2State removes the FIDO2 state for the given server. This should
// be called during server shutdown to prevent memory leaks.
func removeFIDO2State(s *Server) {
	fido2StatesMu.Lock()
	delete(fido2States, s)
	fido2StatesMu.Unlock()
}

// RegisterFIDO2 adds FIDO2 WebAuthn routes to the server's internal mux. It
// must be called after NewServer and before Listen. This is the preferred
// integration path: it registers routes on the same mux that is already
// wrapped by the server's middleware chain, so all FIDO2 routes benefit from
// the existing JSON, logging, and security-headers middleware.
func (s *Server) RegisterFIDO2(manager *fido2.FIDO2AccountsManager, cfg *FIDO2Config) {
	RegisterFIDO2Routes(s, s.mux, manager, cfg)
}

// RegisterFIDO2Routes adds FIDO2 WebAuthn routes to the given mux. The mux
// must be the same ServeMux used by the server. This function is intended to
// be called from the server's route registration code when the fido2 build
// tag is active.
func RegisterFIDO2Routes(s *Server, mux *http.ServeMux, manager *fido2.FIDO2AccountsManager, cfg *FIDO2Config) {
	setFIDO2State(s, &fido2State{manager: manager, config: cfg})

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return authMiddleware(s.accounts, h)
	}

	// Public endpoints (no authentication required).
	mux.HandleFunc("GET /v1/fido2/capabilities", s.handleFIDO2Capabilities)
	mux.HandleFunc("POST /v1/fido2/session", s.handleFIDO2BeginRegistration)
	mux.HandleFunc("GET /v1/fido2/session/{id}", s.handleFIDO2GetSession)
	mux.HandleFunc("POST /v1/fido2/session/{id}/complete", s.handleFIDO2CompleteRegistration)
	mux.HandleFunc("POST /v1/fido2/auth/complete", s.handleFIDO2CompleteLogin)

	// Basic auth required.
	mux.HandleFunc("POST /v1/fido2/auth/begin", authMiddleware(s.accounts, s.handleFIDO2BeginLogin))

	// Full auth required.
	mux.HandleFunc("POST /v1/fido2/enroll", auth(s.handleFIDO2BeginEnrollment))
	mux.HandleFunc("POST /v1/fido2/enroll/{id}/complete", auth(s.handleFIDO2CompleteEnrollment))
	mux.HandleFunc("GET /v1/fido2/credentials", auth(s.handleFIDO2ListCredentials))
	mux.HandleFunc("DELETE /v1/fido2/credentials/{id}", auth(s.handleFIDO2DeleteCredential))
	mux.HandleFunc("PUT /v1/fido2/credentials/{id}/name", auth(s.handleFIDO2RenameCredential))
}
