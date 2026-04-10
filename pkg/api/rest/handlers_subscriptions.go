package rest

import "net/http"

// handleGetSubscriptionConfig handles GET /v1/subscription/configuration.
// Subscription configuration is not yet implemented; returns 501.
func (s *Server) handleGetSubscriptionConfig(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleUpdateSubscriber handles PUT /v1/subscription/{subscriberId}.
// Subscriber management is not yet implemented; returns 501.
func (s *Server) handleUpdateSubscriber(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleGetSubscription handles GET /v1/subscription/{subscriberId}.
// Subscription retrieval is not yet implemented; returns 501.
func (s *Server) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleDeleteSubscriber handles DELETE /v1/subscription/{subscriberId}.
// Subscriber deletion is not yet implemented; returns 501.
func (s *Server) handleDeleteSubscriber(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not implemented")
}
