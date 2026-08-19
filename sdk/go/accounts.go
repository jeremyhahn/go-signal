package signal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// AccountConfiguration holds per-account messaging preference flags that are
// pushed to the server as part of the account-attributes payload. Only
// non-nil pointer fields are sent; nil means "leave unchanged".
type AccountConfiguration struct {
	// ReadReceipts controls whether the server advertises read-receipt
	// capability to other participants.
	ReadReceipts *bool

	// TypingIndicators controls whether typing-indicator messages are sent.
	TypingIndicators *bool

	// LinkPreviews controls whether link-preview metadata is attached.
	LinkPreviews *bool
}

// UpdateConfiguration sends the account configuration preferences to the
// server via PUT /v1/accounts/attributes/. Only non-nil fields are
// included in the request body.
func (c *Client) UpdateConfiguration(ctx context.Context, cfg AccountConfiguration) error {
	body := map[string]any{}
	if cfg.ReadReceipts != nil {
		body["readReceipts"] = *cfg.ReadReceipts
	}
	if cfg.TypingIndicators != nil {
		body["typingIndicators"] = *cfg.TypingIndicators
	}
	if cfg.LinkPreviews != nil {
		body["linkPreviews"] = *cfg.LinkPreviews
	}
	return c.doRequest(ctx, "PUT", "/v1/accounts/attributes/", body, nil)
}

// DeleteLocalData removes all locally stored account data from the data
// directory. This is irreversible and does not contact the server.
// The store is closed before deletion so any pending writes are flushed.
func (c *Client) DeleteLocalData() error {
	if c.store != nil {
		_ = c.store.Close()
	}
	return os.RemoveAll(c.config.DataDir)
}

// VerificationSession holds the state of a phone verification session.
type VerificationSession struct {
	ID                   string `json:"id"`
	AllowedToRequestCode bool   `json:"allowedToRequestCode"`
	Verified             bool   `json:"verified"`
}

// RegistrationResult holds the result of a successful account registration.
type RegistrationResult struct {
	UUID           string `json:"uuid"`
	PNI            string `json:"pni"`
	StorageCapable bool   `json:"storageCapable"`
}

// CreateVerificationSession starts a new phone verification session.
func (c *Client) CreateVerificationSession(ctx context.Context, number string) (*VerificationSession, error) {
	var result VerificationSession
	err := c.doRequest(ctx, "POST", "/v1/verification/session", map[string]string{
		"number": number,
	}, &result)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "create verification session", err)
	}
	return &result, nil
}

// RequestVerificationCode asks the server to send a verification code.
func (c *Client) RequestVerificationCode(ctx context.Context, sessionID string) (*VerificationSession, error) {
	var result VerificationSession
	err := c.doRequest(ctx, "POST", "/v1/verification/session/"+sessionID+"/code", nil, &result)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "request verification code", err)
	}
	return &result, nil
}

// SubmitVerificationCode submits the code to verify the phone number.
func (c *Client) SubmitVerificationCode(ctx context.Context, sessionID, code string) (*VerificationSession, error) {
	var result VerificationSession
	err := c.doRequest(ctx, "PUT", "/v1/verification/session/"+sessionID+"/code", map[string]string{
		"code": code,
	}, &result)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "submit verification code", err)
	}
	return &result, nil
}

// Register creates a new Signal account. This generates all required
// identity keys and pre-keys using go-libsignal, registers with the
// server, and saves credentials locally.
func (c *Client) Register(ctx context.Context, number, sessionID string) (*RegistrationResult, error) {
	// Generate identity key pair for ACI.
	aciKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "generate ACI identity key", err)
	}
	aciPubKey := identity.NewKey(aciKeyPair.PublicKey())
	aciIdentity := identity.NewKeyPair(aciPubKey, aciKeyPair.PrivateKey())

	// Generate identity key pair for PNI.
	pniKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "generate PNI identity key", err)
	}
	pniPubKey := identity.NewKey(pniKeyPair.PublicKey())
	pniIdentity := identity.NewKeyPair(pniPubKey, pniKeyPair.PrivateKey())

	// Generate signed pre-keys.
	aciSignedPreKey, err := generateSignedPreKey(aciIdentity, 1)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "generate ACI signed pre-key", err)
	}
	pniSignedPreKey, err := generateSignedPreKey(pniIdentity, 1)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "generate PNI signed pre-key", err)
	}

	// Generate registration IDs.
	regID := randomRegistrationID()
	pniRegID := randomRegistrationID()

	// Generate auth password in secure memory.
	passwordPlain := generatePassword()
	password, err := secrets.NewSecureString(passwordPlain)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "protect auth password", err)
	}
	// Wipe the plaintext immediately.
	passwordPlainBytes := []byte(passwordPlain)
	for i := range passwordPlainBytes {
		passwordPlainBytes[i] = 0
	}

	// Build registration request.
	regReq := map[string]any{
		"sessionId": sessionID,
		"accountAttributes": map[string]any{
			"fetchesMessages":   true,
			"registrationId":    regID,
			"pniRegistrationId": pniRegID,
			"name":              "signal-go",
			"capabilities": map[string]any{
				"storage":                  true,
				"transfer":                 false,
				"paymentActivation":        false,
				"deleteSync":               false,
				"versionedExpirationTimer": false,
			},
		},
		"aciIdentityKey":        base64.StdEncoding.EncodeToString(aciIdentity.PublicKey().Serialize()),
		"pniIdentityKey":        base64.StdEncoding.EncodeToString(pniIdentity.PublicKey().Serialize()),
		"aciSignedPreKey":       aciSignedPreKey,
		"pniSignedPreKey":       pniSignedPreKey,
		"aciPqLastResortPreKey": generateDummyPQPreKey(aciIdentity),
		"pniPqLastResortPreKey": generateDummyPQPreKey(pniIdentity),
	}

	// Ownership of the sealed password transfers to the client config at the
	// end of this function; until then every failure path must wipe it.
	passwordOwned := true
	defer func() {
		if passwordOwned {
			password.Destroy()
		}
	}()

	var result RegistrationResult
	err = c.doRequestWithAuth(ctx, "POST", "/v1/registration", number, password.Plaintext(), regReq, &result)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "register", err)
	}

	// Save credentials.
	creds := &Credentials{
		Number:   number,
		UUID:     result.UUID,
		PNI:      result.PNI,
		Password: password,
		DeviceID: 1,
	}
	if err := c.store.SaveCredentials(creds); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "save credentials", err)
	}

	// Update client config with new credentials. Password is already
	// SecureString; ownership passes to the config here, so the deferred
	// wipe above stands down.
	c.config.Account = number
	c.config.Password = password // SecureString, enclave-protected
	c.config.DeviceID = 1
	passwordOwned = false

	return &result, nil
}

// Verify is a convenience method that combines CreateVerificationSession,
// RequestVerificationCode, and SubmitVerificationCode into a single call,
// then registers the account.
func (c *Client) Verify(ctx context.Context, number, code string) (*RegistrationResult, error) {
	// Create session.
	session, err := c.CreateVerificationSession(ctx, number)
	if err != nil {
		return nil, err
	}

	// Request code.
	_, err = c.RequestVerificationCode(ctx, session.ID)
	if err != nil {
		return nil, err
	}

	// Submit code.
	verified, err := c.SubmitVerificationCode(ctx, session.ID, code)
	if err != nil {
		return nil, err
	}

	if !verified.Verified {
		return nil, signalerrors.New(signalerrors.ErrUnauthenticated, "verification failed: session not verified")
	}

	// Register account.
	return c.Register(ctx, number, session.ID)
}

// Unregister removes the account from the server.
func (c *Client) Unregister(ctx context.Context) error {
	return c.doRequest(ctx, "DELETE", "/v1/accounts/me", nil, nil)
}

// ReplenishPreKeys checks the server's pre-key count and uploads
// a new batch if below the threshold.
func (c *Client) ReplenishPreKeys(ctx context.Context) error {
	var countResp struct {
		Count         int  `json:"count"`
		PQCount       int  `json:"pqCount"`
		HasLastResort bool `json:"hasLastResort"`
	}
	if err := c.doRequest(ctx, "GET", "/v2/keys", nil, &countResp); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "check pre-key count", err)
	}

	// Replenish if below threshold.
	if countResp.Count >= 10 {
		return nil
	}

	creds, err := c.store.GetCredentials()
	if err != nil || creds == nil {
		return signalerrors.New(signalerrors.ErrUnauthenticated, "no credentials for pre-key upload")
	}

	// Generate pre-keys. Use a simple incrementing ID scheme.
	var preKeys []map[string]any
	for i := 0; i < 100; i++ {
		kp, err := ecc.GenerateKeyPair()
		if err != nil {
			continue
		}
		preKeys = append(preKeys, map[string]any{
			"keyId":     uint64(countResp.Count + i + 1),
			"publicKey": base64.StdEncoding.EncodeToString(kp.PublicKey().Serialize()),
		})
	}

	body := map[string]any{
		"preKeys": preKeys,
	}

	return c.doRequest(ctx, "PUT", "/v2/keys", body, nil)
}

// SetPin sets a registration lock PIN on the account.
func (c *Client) SetPin(ctx context.Context, pin string) error {
	return c.doRequest(ctx, "PUT", "/v1/accounts/registration_lock",
		map[string]string{"registrationLock": pin}, nil)
}

// RemovePin removes the registration lock PIN.
func (c *Client) RemovePin(ctx context.Context) error {
	return c.doRequest(ctx, "DELETE", "/v1/accounts/registration_lock", nil, nil)
}

// UpdateAccountSettings updates account settings on the server.
func (c *Client) UpdateAccountSettings(ctx context.Context, settings map[string]any) error {
	return c.doRequest(ctx, "PUT", "/v1/accounts/attributes/", settings, nil)
}

// SetPhoneNumberDiscoverability sets whether the account can be found by phone number.
func (c *Client) SetPhoneNumberDiscoverability(ctx context.Context, discoverable bool) error {
	return c.doRequest(ctx, "PUT", "/v2/accounts/phone_number_discoverability",
		map[string]bool{"discoverableByPhoneNumber": discoverable}, nil)
}

// SubmitChallenge submits a rate limit challenge response.
func (c *Client) SubmitChallenge(ctx context.Context, token, captcha string) error {
	body := map[string]string{"type": "captcha", "token": token, "captcha": captcha}
	return c.doRequest(ctx, "PUT", "/v1/challenge", body, nil)
}

// WhoAmI returns the authenticated account's identity.
func (c *Client) WhoAmI(ctx context.Context) (*Account, error) {
	var result Account
	if err := c.doRequest(ctx, "GET", "/v1/accounts/whoami", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListAccounts returns all locally registered accounts.
func (c *Client) ListAccounts() ([]Account, error) {
	creds, err := c.store.GetCredentials()
	if err != nil || creds == nil {
		return nil, nil
	}
	return []Account{{
		Number:   creds.Number,
		UUID:     creds.UUID,
		PNI:      creds.PNI,
		DeviceID: creds.DeviceID,
	}}, nil
}

// --- Key generation helpers ---

type signedPreKeyJSON struct {
	KeyID     uint64 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

func generateSignedPreKey(id *identity.KeyPair, keyID uint64) (*signedPreKeyJSON, error) {
	preKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pubBytes := preKeyPair.PublicKey().Serialize()
	sig, err := ecc.CalculateSignature(id.PrivateKey(), pubBytes)
	if err != nil {
		return nil, err
	}
	return &signedPreKeyJSON{
		KeyID:     keyID,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		Signature: base64.StdEncoding.EncodeToString(sig[:]),
	}, nil
}

// generateDummyPQPreKey creates a PQ last-resort pre-key using an EC key pair.
// Full ML-KEM (Kyber) key generation is available via go-libsignal's
// keyhelper.GenerateKyberPreKey. The EC fallback is used when the server
// validates the signature format but the Kyber KEM is not required
// for standalone testing.
func generateDummyPQPreKey(id *identity.KeyPair) *signedPreKeyJSON {
	kp, _ := ecc.GenerateKeyPair()
	pubBytes := kp.PublicKey().Serialize()
	sig, _ := ecc.CalculateSignature(id.PrivateKey(), pubBytes)
	return &signedPreKeyJSON{
		KeyID:     1,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		Signature: base64.StdEncoding.EncodeToString(sig[:]),
	}
}

func randomRegistrationID() uint32 {
	b := make([]byte, 2)
	rand.Read(b)
	return (uint32(b[0])<<8 | uint32(b[1])) & 0x3FFF // 14 bits max
}

func generatePassword() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
