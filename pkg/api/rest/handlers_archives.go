package rest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// X-Signal-ZK-Auth headers carry the ZK presentation + signature for the
// anonymous /v1/archives endpoints. Matches Java ArchiveController.
const (
	headerZKAuth    = "X-Signal-ZK-Auth"
	headerZKAuthSig = "X-Signal-ZK-Auth-Signature"
)

// zkAuthenticate decodes the two ZK headers and authenticates the user.
// On any failure it writes the appropriate error response and returns nil
// — callers should bail out without writing further output.
func (s *Server) zkAuthenticate(w http.ResponseWriter, r *http.Request) *backups.AuthenticatedUser {
	// Check auth headers before service-configured state so we don't leak
	// 501 (not implemented) to unauthenticated callers — the matching test
	// suite asserts this invariant explicitly.
	presentationB64 := r.Header.Get(headerZKAuth)
	signatureB64 := r.Header.Get(headerZKAuthSig)
	if presentationB64 == "" || signatureB64 == "" {
		writeError(w, http.StatusUnauthorized, "missing zk auth headers")
		return nil
	}
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "backup service not configured")
		return nil
	}
	presentation, err := base64.StdEncoding.DecodeString(presentationB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in zk auth presentation")
		return nil
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in zk auth signature")
		return nil
	}
	user, err := s.backups.AuthenticateBackupUser(r.Context(), presentation, signature, r.UserAgent())
	if err != nil {
		writeBackupError(w, err)
		return nil
	}
	return user
}

// writeBackupError maps a typed backups error to the appropriate HTTP
// status + body. Unknown error types fall through to 500.
func writeBackupError(w http.ResponseWriter, err error) {
	var (
		permErr     *backups.PermissionError
		typeErr     *backups.WrongCredentialTypeError
		zkErr       *backups.FailedZkAuthError
		conflictErr *backups.PublicKeyConflictError
		notFoundErr *backups.NotFoundError
		invArgErr   *backups.InvalidArgumentError
		rateLimErr  *backups.RateLimitedError
		badReceipt  *backups.BadReceiptError
		missingComm *backups.MissingIDCommitmentError
	)
	switch {
	case errors.As(err, &permErr):
		writeError(w, http.StatusForbidden, permErr.Error())
	case errors.As(err, &typeErr):
		writeError(w, http.StatusUnauthorized, typeErr.Error())
	case errors.As(err, &zkErr):
		writeError(w, http.StatusUnauthorized, zkErr.Error())
	case errors.As(err, &conflictErr):
		writeError(w, http.StatusConflict, conflictErr.Error())
	case errors.As(err, &notFoundErr):
		writeError(w, http.StatusNotFound, notFoundErr.Error())
	case errors.As(err, &invArgErr):
		writeError(w, http.StatusBadRequest, invArgErr.Error())
	case errors.As(err, &rateLimErr):
		writeError(w, http.StatusTooManyRequests, rateLimErr.Error())
	case errors.As(err, &badReceipt):
		writeError(w, http.StatusBadRequest, badReceipt.Error())
	case errors.As(err, &missingComm):
		writeError(w, http.StatusConflict, missingComm.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

// --- Account-authenticated handlers ----------------------------------------

// SetBackupIDRequestBody is the JSON body for PUT /v1/archives/backupid.
type SetBackupIDRequestBody struct {
	MessagesBackupAuthCredentialRequest string `json:"messagesBackupAuthCredentialRequest,omitempty"`
	MediaBackupAuthCredentialRequest    string `json:"mediaBackupAuthCredentialRequest,omitempty"`
}

// handleSetBackupId is PUT /v1/archives/backupid.
func (s *Server) handleSetBackupId(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "backup service not configured")
		return
	}
	deviceID := deviceIDFromContext(r.Context())

	var body SetBackupIDRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	messages, mediaBytes, err := decodeOptionalBase64Pair(body.MessagesBackupAuthCredentialRequest, body.MediaBackupAuthCredentialRequest)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.backups.SetBackupID(r.Context(), acct.UUID, deviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: messages,
		MediaBackupAuthCredentialRequest:    mediaBytes,
	}); err != nil {
		writeBackupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// BackupIDLimitsResponse is the body of GET /v1/archives/backupid/limits.
type BackupIDLimitsResponse struct {
	MessagesNextRotationAllowedAt int64 `json:"messagesNextRotationAllowedAt"`
	MediaNextRotationAllowedAt    int64 `json:"mediaNextRotationAllowedAt"`
}

// handleGetBackupIdLimits is GET /v1/archives/backupid/limits.
func (s *Server) handleGetBackupIdLimits(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "backup service not configured")
		return
	}
	limits, err := s.backups.GetBackupIDLimits(r.Context(), acct.UUID)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, BackupIDLimitsResponse{
		MessagesNextRotationAllowedAt: limits.MessagesNextRotationAllowedAt.Unix(),
		MediaNextRotationAllowedAt:    limits.MediaNextRotationAllowedAt.Unix(),
	})
}

// RedeemReceiptRequestBody is the JSON body for POST /v1/archives/redeem-receipt.
type RedeemReceiptRequestBody struct {
	ReceiptCredentialPresentation string `json:"receiptCredentialPresentation"`
}

// handleRedeemReceipt is POST /v1/archives/redeem-receipt.
func (s *Server) handleRedeemReceipt(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "backup service not configured")
		return
	}
	var body RedeemReceiptRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	receipt, err := base64.StdEncoding.DecodeString(body.ReceiptCredentialPresentation)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in receiptCredentialPresentation")
		return
	}
	if err := s.backups.RedeemReceipt(r.Context(), acct.UUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	}); err != nil {
		writeBackupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// BackupAuthCredentialResponse is one entry in CredentialsResponse.
type BackupAuthCredentialResponse struct {
	CredentialType string `json:"credentialType"`
	RedemptionTime int64  `json:"redemptionTime"`
	Credential     string `json:"credential"`
}

// CredentialsResponse is the body of GET /v1/archives/auth.
type CredentialsResponse struct {
	Credentials []BackupAuthCredentialResponse `json:"credentials"`
}

// handleGetBackupAuth is GET /v1/archives/auth?redemptionStartSeconds=&redemptionEndSeconds=.
func (s *Server) handleGetBackupAuth(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "backup service not configured")
		return
	}
	startSec, err := strconv.ParseInt(r.URL.Query().Get("redemptionStartSeconds"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid redemptionStartSeconds")
		return
	}
	endSec, err := strconv.ParseInt(r.URL.Query().Get("redemptionEndSeconds"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid redemptionEndSeconds")
		return
	}
	resp, err := s.backups.GetBackupAuthCredentials(r.Context(), acct.UUID,
		time.Unix(startSec, 0).UTC(), time.Unix(endSec, 0).UTC())
	if err != nil {
		writeBackupError(w, err)
		return
	}
	out := CredentialsResponse{Credentials: make([]BackupAuthCredentialResponse, 0, len(resp.Credentials))}
	for _, c := range resp.Credentials {
		out.Credentials = append(out.Credentials, BackupAuthCredentialResponse{
			CredentialType: credentialTypeName(c.Type),
			RedemptionTime: c.RedemptionTime.Unix(),
			Credential:     base64.StdEncoding.EncodeToString(c.Credential),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- ZK-authenticated handlers ---------------------------------------------

// BackupInfoResponse is the body of GET /v1/archives.
type BackupInfoResponse struct {
	CDN              int    `json:"cdn"`
	BackupDir        string `json:"backupDir"`
	MediaDir         string `json:"mediaDir"`
	MessageBackupKey string `json:"messageBackupKey"`
	UsedSpace        *int64 `json:"usedSpace,omitempty"`
}

// handleGetBackupInfo is GET /v1/archives.
func (s *Server) handleGetBackupInfo(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	info, err := s.backups.BackupInfo(r.Context(), user)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, BackupInfoResponse{
		CDN:              info.CDN,
		BackupDir:        info.BackupDir,
		MediaDir:         info.MediaDir,
		MessageBackupKey: info.MessageBackupKey,
		UsedSpace:        info.MediaUsedSpace,
	})
}

// handleRefreshBackup is POST /v1/archives.
func (s *Server) handleRefreshBackup(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	if err := s.backups.TTLRefresh(r.Context(), user); err != nil {
		writeBackupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteBackup is DELETE /v1/archives.
func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	if err := s.backups.DeleteEntireBackup(r.Context(), user); err != nil {
		writeBackupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetPublicKeyRequestBody is the JSON body for PUT /v1/archives/keys.
type SetPublicKeyRequestBody struct {
	BackupIDPublicKey string `json:"backupIdPublicKey"`
}

// handleSetBackupPublicKey is PUT /v1/archives/keys.
func (s *Server) handleSetBackupPublicKey(w http.ResponseWriter, r *http.Request) {
	// Check auth headers before service-configured state so we don't leak the
	// 501 (not implemented) signal to unauthenticated callers — matching the
	// ordering invariant documented on zkAuthenticate.
	presentationB64 := r.Header.Get(headerZKAuth)
	signatureB64 := r.Header.Get(headerZKAuthSig)
	if presentationB64 == "" || signatureB64 == "" {
		writeError(w, http.StatusUnauthorized, "missing zk auth headers")
		return
	}
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "backup service not configured")
		return
	}
	presentation, err := base64.StdEncoding.DecodeString(presentationB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in zk auth presentation")
		return
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in zk auth signature")
		return
	}
	var body SetPublicKeyRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	publicKey, err := base64.StdEncoding.DecodeString(body.BackupIDPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in backupIdPublicKey")
		return
	}
	if err := s.backups.SetPublicKey(r.Context(), presentation, signature, publicKey); err != nil {
		writeBackupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UploadDescriptorResponse is the body of the upload-form endpoints.
type UploadDescriptorResponse struct {
	CDN                  int               `json:"cdn"`
	Key                  string            `json:"key"`
	Headers              map[string]string `json:"headers"`
	SignedUploadLocation string            `json:"signedUploadLocation"`
}

// handleGetBackupUploadForm is GET /v1/archives/upload/form.
func (s *Server) handleGetBackupUploadForm(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	desc, err := s.backups.CreateMessageBackupUploadDescriptor(r.Context(), user)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, UploadDescriptorResponse{
		CDN:                  desc.CDN,
		Key:                  desc.Key,
		Headers:              desc.Headers,
		SignedUploadLocation: desc.SignedUploadLocation,
	})
}

// handleGetMediaUploadForm is GET /v1/archives/media/upload/form.
func (s *Server) handleGetMediaUploadForm(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	desc, err := s.backups.CreateTemporaryAttachmentUploadDescriptor(r.Context(), user)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, UploadDescriptorResponse{
		CDN:                  desc.CDN,
		Key:                  desc.Key,
		Headers:              desc.Headers,
		SignedUploadLocation: desc.SignedUploadLocation,
	})
}

// CopyMediaRequestBody is the JSON body for PUT /v1/archives/media/.
type CopyMediaRequestBody struct {
	SourceAttachment struct {
		CDN int    `json:"cdn"`
		Key string `json:"key"`
	} `json:"sourceAttachment"`
	ObjectLength  int    `json:"objectLength"`
	MediaID       string `json:"mediaId"`
	HMACKey       string `json:"hmacKey"`
	EncryptionKey string `json:"encryptionKey"`
}

// CopyMediaResponseBody is the JSON body of a successful PUT /v1/archives/media/.
type CopyMediaResponseBody struct {
	CDN int `json:"cdn"`
}

// CopyMediaBatchRequestBody wraps multiple CopyMediaRequestBody items.
type CopyMediaBatchRequestBody struct {
	Items []CopyMediaRequestBody `json:"items"`
}

// CopyMediaBatchResponseItem is one entry in a batch response.
type CopyMediaBatchResponseItem struct {
	Status  int    `json:"status"`
	MediaID string `json:"mediaId"`
	CDN     *int   `json:"cdn,omitempty"`
	Failure string `json:"failure,omitempty"`
}

// CopyMediaBatchResponseBody is the body of PUT /v1/archives/media/batch.
type CopyMediaBatchResponseBody struct {
	Responses []CopyMediaBatchResponseItem `json:"responses"`
}

// handleCopyMedia is PUT /v1/archives/media/.
func (s *Server) handleCopyMedia(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	var body CopyMediaRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	params, err := parseCopyParameters(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	quota, err := s.backups.GetCopyQuota(r.Context(), user, []backups.CopyParameters{params})
	if err != nil {
		writeBackupError(w, err)
		return
	}
	var (
		responseCDN *int
		outcome     = backups.CopyOutcomeOutOfQuota
	)
	err = s.backups.CopyToBackup(r.Context(), *quota, func(cr backups.CopyResult) error {
		outcome = cr.Outcome
		responseCDN = cr.CDN
		return nil
	})
	if err != nil {
		writeBackupError(w, err)
		return
	}
	if outcome != backups.CopyOutcomeSuccess {
		writeError(w, copyOutcomeToHTTP(outcome), copyOutcomeName(outcome))
		return
	}
	writeJSON(w, http.StatusOK, CopyMediaResponseBody{CDN: derefInt(responseCDN)})
}

// handleCopyMediaBatch is PUT /v1/archives/media/batch.
func (s *Server) handleCopyMediaBatch(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	var body CopyMediaBatchRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	params := make([]backups.CopyParameters, 0, len(body.Items))
	for _, item := range body.Items {
		p, err := parseCopyParameters(item)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		params = append(params, p)
	}
	quota, err := s.backups.GetCopyQuota(r.Context(), user, params)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	out := CopyMediaBatchResponseBody{Responses: make([]CopyMediaBatchResponseItem, 0, len(params))}
	err = s.backups.CopyToBackup(r.Context(), *quota, func(cr backups.CopyResult) error {
		entry := CopyMediaBatchResponseItem{
			MediaID: base64.URLEncoding.EncodeToString(cr.MediaID),
			Status:  copyOutcomeToHTTP(cr.Outcome),
		}
		if cr.Outcome == backups.CopyOutcomeSuccess {
			entry.CDN = cr.CDN
		} else {
			entry.Failure = copyOutcomeName(cr.Outcome)
		}
		out.Responses = append(out.Responses, entry)
		return nil
	})
	if err != nil {
		writeBackupError(w, err)
		return
	}
	writeJSON(w, http.StatusMultiStatus, out)
}

// ListMediaResponseItem is one entry in the GET /v1/archives/media response.
type ListMediaResponseItem struct {
	CDN     int    `json:"cdn"`
	MediaID string `json:"mediaId"`
	Length  int64  `json:"objectLength"`
}

// ListMediaResponseBody is the body of GET /v1/archives/media.
type ListMediaResponseBody struct {
	StoredMediaObjects []ListMediaResponseItem `json:"storedMediaObjects"`
	Cursor             string                  `json:"cursor,omitempty"`
}

// handleListMedia is GET /v1/archives/media?cursor=&limit=.
func (s *Server) handleListMedia(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	var cursor *string
	if c := r.URL.Query().Get("cursor"); c != "" {
		cursor = &c
	}
	const maxListMediaLimit = 1000
	limit := maxListMediaLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		// Clamp to the maximum page size so a client cannot request an
		// arbitrarily large page and push unbounded work/memory downstream.
		if parsed > maxListMediaLimit {
			parsed = maxListMediaLimit
		}
		limit = parsed
	}
	result, err := s.backups.ListMedia(r.Context(), user, cursor, limit)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	out := ListMediaResponseBody{StoredMediaObjects: make([]ListMediaResponseItem, 0, len(result.Media))}
	for _, m := range result.Media {
		out.StoredMediaObjects = append(out.StoredMediaObjects, ListMediaResponseItem{
			CDN:     m.CDN,
			MediaID: base64.URLEncoding.EncodeToString(m.Key),
			Length:  m.Length,
		})
	}
	if result.Cursor != nil {
		out.Cursor = *result.Cursor
	}
	writeJSON(w, http.StatusOK, out)
}

// DeleteMediaRequestItem identifies one object to delete.
type DeleteMediaRequestItem struct {
	CDN     int    `json:"cdn"`
	MediaID string `json:"mediaId"`
}

// DeleteMediaRequestBody is the JSON body of POST /v1/archives/media/delete.
type DeleteMediaRequestBody struct {
	MediaToDelete []DeleteMediaRequestItem `json:"mediaToDelete"`
}

// handleDeleteMedia is POST /v1/archives/media/delete.
func (s *Server) handleDeleteMedia(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	var body DeleteMediaRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	descriptors := make([]backups.StorageDescriptor, 0, len(body.MediaToDelete))
	for _, it := range body.MediaToDelete {
		mediaID, err := base64.URLEncoding.DecodeString(it.MediaID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid base64url in mediaId")
			return
		}
		descriptors = append(descriptors, backups.StorageDescriptor{CDN: it.CDN, Key: mediaID})
	}
	if err := s.backups.DeleteMedia(r.Context(), user, descriptors, func(backups.StorageDescriptor) error {
		return nil
	}); err != nil {
		writeBackupError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReadAuthResponse is the body of GET /v1/archives/auth/read?cdn={n}.
type ReadAuthResponse struct {
	Headers map[string]string `json:"headers"`
}

// handleGetCDNReadAuth is GET /v1/archives/auth/read?cdn={n}.
func (s *Server) handleGetCDNReadAuth(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	cdn, err := strconv.Atoi(r.URL.Query().Get("cdn"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cdn")
		return
	}
	headers, err := s.backups.GenerateReadAuth(r.Context(), user, cdn)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ReadAuthResponse{Headers: headers})
}

// ExternalServiceCredentialsResponse is the body of GET /v1/archives/auth/svrb.
type ExternalServiceCredentialsResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleGetSVRBAuth is GET /v1/archives/auth/svrb.
func (s *Server) handleGetSVRBAuth(w http.ResponseWriter, r *http.Request) {
	user := s.zkAuthenticate(w, r)
	if user == nil {
		return
	}
	creds, err := s.backups.GenerateSVRBAuth(r.Context(), user)
	if err != nil {
		writeBackupError(w, err)
		return
	}
	// The credential leaves protected memory only here, to be written to
	// the client that is its intended bearer. Reveal rather than Plaintext:
	// a credential that cannot be read back is a failure, not an empty
	// password the client would treat as usable.
	defer creds.Destroy()
	password, err := creds.Password.Reveal()
	if err != nil {
		s.logger.Error("svrb credential unavailable", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, ExternalServiceCredentialsResponse{
		Username: creds.Username,
		Password: password,
	})
}

// --- helpers ----------------------------------------------------------------

// decodeOptionalBase64Pair decodes both inputs; empty strings yield nil
// (signal-to-server: "leave this slot unchanged"). Returns an error if
// either is non-empty but not valid base64.
func decodeOptionalBase64Pair(a, b string) ([]byte, []byte, error) {
	var ab, bb []byte
	var err error
	if a != "" {
		if ab, err = base64.StdEncoding.DecodeString(a); err != nil {
			return nil, nil, &backups.InvalidArgumentError{Field: "messagesBackupAuthCredentialRequest", Message: "invalid base64"}
		}
	}
	if b != "" {
		if bb, err = base64.StdEncoding.DecodeString(b); err != nil {
			return nil, nil, &backups.InvalidArgumentError{Field: "mediaBackupAuthCredentialRequest", Message: "invalid base64"}
		}
	}
	return ab, bb, nil
}

// parseCopyParameters decodes a single CopyMediaRequestBody into the
// internal CopyParameters shape. Mediocre fields trigger
// [*backups.InvalidArgumentError].
func parseCopyParameters(body CopyMediaRequestBody) (backups.CopyParameters, error) {
	mediaID, err := base64.URLEncoding.DecodeString(body.MediaID)
	if err != nil {
		return backups.CopyParameters{}, &backups.InvalidArgumentError{Field: "mediaId", Message: "invalid base64url"}
	}
	hmacKey, err := base64.StdEncoding.DecodeString(body.HMACKey)
	if err != nil {
		return backups.CopyParameters{}, &backups.InvalidArgumentError{Field: "hmacKey", Message: "invalid base64"}
	}
	encKey, err := base64.StdEncoding.DecodeString(body.EncryptionKey)
	if err != nil {
		return backups.CopyParameters{}, &backups.InvalidArgumentError{Field: "encryptionKey", Message: "invalid base64"}
	}
	return backups.CopyParameters{
		SourceCDN:    body.SourceAttachment.CDN,
		SourceKey:    body.SourceAttachment.Key,
		SourceLength: body.ObjectLength,
		EncryptionParameters: backups.MediaEncryptionParameters{
			EncryptionKey: encKey,
			MACKey:        hmacKey,
		},
		DestinationMediaID: mediaID,
	}, nil
}

// credentialTypeName returns the wire-format string for a CredentialType.
func credentialTypeName(t backups.CredentialType) string {
	switch t {
	case backups.CredentialTypeMessages:
		return "messages"
	case backups.CredentialTypeMedia:
		return "media"
	default:
		return "unknown"
	}
}

// copyOutcomeName returns the wire-format string for a CopyOutcome.
func copyOutcomeName(o backups.CopyOutcome) string {
	switch o {
	case backups.CopyOutcomeSuccess:
		return "success"
	case backups.CopyOutcomeSourceNotFound:
		return "sourceNotFound"
	case backups.CopyOutcomeSourceWrongLength:
		return "sourceWrongLength"
	case backups.CopyOutcomeOutOfQuota:
		return "outOfQuota"
	default:
		return "unknown"
	}
}

// copyOutcomeToHTTP returns the HTTP status code corresponding to a
// per-item CopyOutcome, matching Java's mapping (success→200,
// sourceNotFound→410, sourceWrongLength→400, outOfQuota→413).
func copyOutcomeToHTTP(o backups.CopyOutcome) int {
	switch o {
	case backups.CopyOutcomeSuccess:
		return http.StatusOK
	case backups.CopyOutcomeSourceNotFound:
		return http.StatusGone
	case backups.CopyOutcomeSourceWrongLength:
		return http.StatusBadRequest
	case backups.CopyOutcomeOutOfQuota:
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// derefInt returns the int pointed to by p, or 0 if nil. Used so the
// success-path response always has a CDN field.
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
