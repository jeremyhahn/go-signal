package rest

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-signal/pkg/certificates"
)

// handleGetDeliveryCertificate processes GET /v1/certificate/delivery and
// returns a signed delivery certificate for sealed-sender messaging. The
// optional includeE164 query parameter controls whether the sender's phone
// number is embedded in the certificate.
func (s *Server) handleGetDeliveryCertificate(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	includeE164 := true
	if v := r.URL.Query().Get("includeE164"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid includeE164 parameter")
			return
		}
		includeE164 = parsed
	}

	// Issue the certificate for the device that actually authenticated, so
	// sealed-sender delivery certificates carry the correct source device ID.
	deviceID := uint32(deviceIDFromContext(r.Context()))

	cert, err := s.certificates.GetDeliveryCertificate(
		r.Context(),
		acct.UUID,
		acct.Number,
		deviceID,
		acct.IdentityKey,
		includeE164,
	)
	if err != nil {
		s.logger.Error("failed to generate delivery certificate",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()),
		)
		writeError(w, http.StatusInternalServerError, "failed to generate certificate")
		return
	}

	writeJSON(w, http.StatusOK, DeliveryCertificateResponse{
		Certificate:       string(cert.Certificate),
		CertificateExpiry: cert.CertificateExpiry,
	})
}

// handleGetGroupCredentials processes GET /v1/certificate/auth/group and
// returns time-limited group send authentication credentials for the
// specified time range.
func (s *Server) handleGetGroupCredentials(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	startStr := r.URL.Query().Get("redemptionStartSeconds")
	endStr := r.URL.Query().Get("redemptionEndSeconds")

	if startStr == "" || endStr == "" {
		writeError(w, http.StatusBadRequest, "redemptionStartSeconds and redemptionEndSeconds are required")
		return
	}

	startSeconds, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid redemptionStartSeconds")
		return
	}

	endSeconds, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid redemptionEndSeconds")
		return
	}

	creds, err := s.certificates.GetGroupCredentials(
		r.Context(),
		acct.UUID,
		acct.PNI,
		startSeconds,
		endSeconds,
	)
	if err != nil {
		s.logger.Error("failed to generate group credentials",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()),
		)
		// Only genuine client-input errors map to 400; certificate
		// generation, key, and zkgroup failures are server faults (500).
		var timeRangeErr *certificates.InvalidTimeRangeError
		var uuidErr *certificates.InvalidUUIDError
		if errors.As(err, &timeRangeErr) || errors.As(err, &uuidErr) {
			writeError(w, http.StatusBadRequest, "invalid credential request")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to generate group credentials")
		return
	}

	writeJSON(w, http.StatusOK, creds)
}
