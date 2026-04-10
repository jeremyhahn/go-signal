package rest

import "net/http"

// handleRedeemDonationReceipt handles POST /v1/donation/redeem-receipt.
// Donation receipt redemption is not yet implemented; returns 501.
func (s *Server) handleRedeemDonationReceipt(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}
