package certificates

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// jsonMarshal is the JSON marshaling function used internally. It defaults to
// json.Marshal and can be replaced in tests to simulate marshaling failures.
var jsonMarshal = json.Marshal

// randRead is the random-bytes reader used internally. It defaults to
// rand.Read and can be replaced in tests to simulate randomness failures.
var randRead = rand.Read

// certificateValidityDuration defines how long a delivery certificate remains
// valid from the time of issuance.
const certificateValidityDuration = 24 * time.Hour

// maxCredentialRangeDays limits the maximum number of daily credentials that
// can be generated in a single request.
const maxCredentialRangeDays = 7

// secondsPerDay is the number of seconds in one day, used to iterate daily
// credential windows.
const secondsPerDay int64 = 86400

// ed25519PrivKeySize is the canonical byte length of an Ed25519 private key.
const ed25519PrivKeySize = ed25519.PrivateKeySize

// CertificatesManager generates delivery certificates and group credentials
// for sealed-sender messaging. It uses an Ed25519 signing key (when
// configured) to produce delivery certificate signatures, falling back to
// HMAC-SHA256 for compatibility when no Ed25519 key is set. When
// authServerSecret is set, group credentials are issued via the zkgroup
// AuthCredentialWithPni protocol; otherwise HMAC-SHA256 is used.
// When callingZKParams is set, it also issues CallLinkAuthCredentials
// alongside group credentials.
type CertificatesManager struct {
	// signingKey is the legacy HMAC signing key, used for delivery cert
	// fallback and HMAC group credentials when zkgroup is not configured.
	signingKey *secrets.SecureString

	// keyMu guards ed25519Secret and ed25519PubKeyID. Readers hold it for
	// the whole open-copy-use sequence, so a rotation cannot destroy a
	// secret an in-flight signature is still reading; SetEd25519SigningKey
	// and Destroy take it exclusively. Rotation is rare and signing is not,
	// hence RWMutex rather than a bare Mutex.
	keyMu sync.RWMutex

	// ed25519Secret holds the Ed25519 private key in the shared
	// protected-memory abstraction. When non-nil, Ed25519 signing replaces
	// HMAC-SHA256. The key material is only briefly exposed during signing
	// and the working copy is destroyed immediately after use.
	// Guarded by keyMu.
	ed25519Secret *secure.Secret

	// ed25519PubKeyID is an opaque key identifier embedded in delivery
	// certificates so clients can select the correct verification key.
	// Guarded by keyMu.
	ed25519PubKeyID uint32

	// authServerSecret is the full zkgroup server secret used to issue
	// AuthCredentialWithPni group credentials.
	authServerSecret *zkgroup.ServerSecretParams

	// callingZKParams is the generic server secret used to issue
	// CallLinkAuthCredentials alongside group credentials.
	callingZKParams *zkgroup.GenericServerSecretParams

	logger *slog.Logger
}

// NewCertificatesManager creates a new CertificatesManager with the given
// signing key and logger. The signing key is used for HMAC-SHA256 fallback
// signing on generated certificates. The manager takes ownership of the
// SecureString and will destroy it when Destroy is called.
func NewCertificatesManager(signingKey *secrets.SecureString, logger *slog.Logger) *CertificatesManager {
	return &CertificatesManager{
		signingKey: signingKey,
		logger:     logger,
	}
}

// Destroy wipes all key material from protected memory. It should be called
// during graceful shutdown after all in-flight requests have completed.
func (m *CertificatesManager) Destroy() {
	if m.signingKey != nil {
		m.signingKey.Destroy()
		m.signingKey = nil
	}
	m.keyMu.Lock()
	if m.ed25519Secret != nil {
		m.ed25519Secret.Destroy()
		m.ed25519Secret = nil
	}
	m.keyMu.Unlock()
	// Zero zkgroup server secrets by releasing the pointer references so GC
	// can collect them; the underlying C memory is managed by the zkgroup
	// library itself.
	if m.authServerSecret != nil {
		m.authServerSecret = nil
	}
	if m.callingZKParams != nil {
		m.callingZKParams = nil
	}
}

// SetCallingZKParams configures the calling zkgroup parameters used to issue
// CallLinkAuthCredentials alongside group credentials.
func (m *CertificatesManager) SetCallingZKParams(params *zkgroup.GenericServerSecretParams) {
	m.callingZKParams = params
}

// SetAuthServerSecret configures the full zkgroup server secret used to issue
// AuthCredentialWithPniZkc group credentials. When set, GetGroupCredentials
// produces proper zkgroup credentials instead of HMAC-SHA256 fallbacks.
func (m *CertificatesManager) SetAuthServerSecret(params *zkgroup.ServerSecretParams) {
	m.authServerSecret = params
}

// SetEd25519SigningKey configures the Ed25519 private key used to sign
// delivery certificates. The privKey must be exactly ed25519.PrivateKeySize
// bytes. The pubKeyID is an opaque identifier included in the certificate
// so clients can select the correct verification key. When set, delivery
// certificate signing uses Ed25519 instead of HMAC-SHA256.
func (m *CertificatesManager) SetEd25519SigningKey(ctx context.Context, privKey ed25519.PrivateKey, pubKeyID uint32) error {
	if len(privKey) != ed25519PrivKeySize {
		return &Ed25519KeyError{Cause: &invalidKeyLengthError{
			Got:  len(privKey),
			Want: ed25519PrivKeySize,
		}}
	}
	// NewSecret copies the bytes into an enclave and zeros the source slice
	// on return; the sealed material can only be read back through Open.
	sec, err := secure.NewSecret(ctx, privKey)
	if err != nil {
		return &Ed25519KeyError{Cause: err}
	}
	// Seal first, then swap, then wipe the key we replaced: a rotation must
	// not leave the previous private key resident and unreachable, and a
	// failed seal above must not have disturbed the key in use.
	// The swap and the wipe both happen under the write lock: a reader that
	// already holds the retired secret holds the read lock, so Lock waits it
	// out and the destroy cannot land mid-signature.
	m.keyMu.Lock()
	previous := m.ed25519Secret
	m.ed25519Secret = sec
	m.ed25519PubKeyID = pubKeyID
	previous.Destroy()
	m.keyMu.Unlock()
	return nil
}

// Ed25519PublicKey returns the Ed25519 public key corresponding to the
// configured private key, or nil if no Ed25519 key has been configured.
// The private key is only briefly unlocked to derive the public key and is
// re-sealed immediately after use.
func (m *CertificatesManager) Ed25519PublicKey(ctx context.Context) ed25519.PublicKey {
	var pub ed25519.PublicKey
	// Derive the public key from the locked bytes via a temporary copy; the
	// copy is zeroed by useEd25519Key before this returns.
	_, err := m.useEd25519Key(ctx, func(priv ed25519.PrivateKey) error {
		derived, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return &Ed25519KeyError{Cause: errNotAnEd25519Key}
		}
		pub = derived
		return nil
	})
	if err != nil {
		return nil
	}
	return pub
}

// errNotAnEd25519Key is returned when a sealed key does not yield an Ed25519
// public key — structurally impossible for a key that passed the length check
// in SetEd25519SigningKey, but the type assertion is not ours to elide.
var errNotAnEd25519Key = errors.New("certificates: sealed key is not an Ed25519 private key")

// useEd25519Key runs fn with a temporary heap copy of the configured Ed25519
// private key, or reports that no key is configured. The key lock is held for
// read across the whole call, so a concurrent SetEd25519SigningKey cannot wipe
// the secret while fn is using it; the heap copy is zeroed on the way out.
//
// The copy exists because crypto/ed25519 registers a weak pointer on the key
// (required by Go's FIPS140 cache) and so cannot be handed protected memory
// directly.
func (m *CertificatesManager) useEd25519Key(ctx context.Context, fn func(priv ed25519.PrivateKey) error) (bool, error) {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()

	if m.ed25519Secret == nil {
		return false, nil
	}
	buf, err := m.ed25519Secret.Open(ctx)
	if err != nil {
		return true, err
	}
	copied, err := secure.CopyOut(buf)
	buf.Destroy()
	if err != nil {
		return true, err
	}
	priv := ed25519.PrivateKey(copied)
	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()
	if err != nil {
		return true, err
	}
	return true, fn(priv)
}

// hasEd25519Key reports whether an Ed25519 signing key is configured.
func (m *CertificatesManager) hasEd25519Key() bool {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	return m.ed25519Secret != nil
}

// GetDeliveryCertificate generates a delivery certificate for the specified
// sender. The certificate encodes the sender's identity and is signed with the
// server's signing key. When an Ed25519 key is configured, Ed25519 is used;
// otherwise the method falls back to HMAC-SHA256. When includeE164 is false,
// the phone number is omitted from the certificate to support anonymous
// sealed-sender delivery.
//
// Deprecated: this method emits a JSON-encoded envelope with raw Ed25519
// or HMAC over a JSON payload. That format is NOT byte-wire compatible
// with Rust libsignal or the Java Signal-Server reference. New code MUST
// use BuildSignalSenderCertificate (in signal_compat.go) which delegates
// to go-libsignal/pkg/sealed and produces a protobuf-encoded,
// XEdDSA-signed Signal SenderCertificate. This method is retained only
// to keep existing API consumers compiling until they migrate; it will
// be removed in a future release.
func (m *CertificatesManager) GetDeliveryCertificate(
	ctx context.Context,
	uuid string,
	e164 string,
	deviceID uint32,
	identityKey []byte,
	includeE164 bool,
) (*DeliveryCertificate, error) {
	expiry := time.Now().Add(certificateValidityDuration)
	expiryMillis := expiry.UnixMilli()

	senderCert := SenderCertificate{
		SenderUUID:     uuid,
		SenderDeviceID: deviceID,
		Expiration:     expiryMillis,
		IdentityKey:    identityKey,
	}
	if includeE164 {
		senderCert.SenderE164 = e164
	}

	// Sign with Ed25519 when configured; fall back to HMAC-SHA256 otherwise.
	signer, err := m.signCertificate(ctx, &senderCert)
	if err != nil {
		return nil, &CertificateGenerationError{Operation: "sign", Cause: err}
	}
	senderCert.Signer = signer

	certBytes, err := jsonMarshal(senderCert)
	if err != nil {
		return nil, &CertificateGenerationError{Operation: "marshal", Cause: err}
	}

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(certBytes)))
	base64.StdEncoding.Encode(encoded, certBytes)

	m.logger.DebugContext(ctx, "generated delivery certificate",
		slog.String("uuid", uuid),
		slog.Int64("expiry", expiryMillis),
		slog.Bool("includeE164", includeE164),
		slog.Bool("ed25519", m.hasEd25519Key()),
	)

	return &DeliveryCertificate{
		Certificate:       encoded,
		CertificateExpiry: expiryMillis,
	}, nil
}

// GetGroupCredentials generates daily group send credentials for the specified
// account covering the time range from startSeconds to endSeconds (inclusive,
// Unix timestamps). Each credential is keyed to a specific day and can be
// redeemed during that day's window.
//
// When authServerSecret is configured, credentials are issued using the
// zkgroup AuthCredentialWithPniZkc protocol; otherwise HMAC-SHA256 is used.
func (m *CertificatesManager) GetGroupCredentials(
	ctx context.Context,
	uuid string,
	pni string,
	startSeconds int64,
	endSeconds int64,
) (*GroupCredentials, error) {
	if startSeconds > endSeconds {
		return nil, &InvalidTimeRangeError{Message: "start must not be after end"}
	}

	startDay := startSeconds / secondsPerDay
	endDay := endSeconds / secondsPerDay

	if endDay-startDay+1 > int64(maxCredentialRangeDays) {
		return nil, &InvalidTimeRangeError{Message: "range exceeds maximum of 7 days"}
	}

	credentials := make([]GroupCredential, 0, endDay-startDay+1)

	for day := startDay; day <= endDay; day++ {
		redemptionTime := day * secondsPerDay

		var (
			credential []byte
			err        error
		)

		if m.authServerSecret != nil {
			credential, err = m.issueAuthCredentialWithPni(uuid, pni, redemptionTime)
		} else {
			credential, err = m.generateGroupCredential(ctx, uuid, redemptionTime)
		}

		if err != nil {
			return nil, &CertificateGenerationError{Operation: "group-credential", Cause: err}
		}

		credentials = append(credentials, GroupCredential{
			Credential:     credential,
			RedemptionTime: redemptionTime,
		})
	}

	// Issue CallLinkAuthCredentials alongside group credentials when configured.
	var callLinkCreds []CallLinkAuthCredential
	if m.callingZKParams != nil {
		var clErr error
		callLinkCreds, clErr = m.issueCallLinkAuthCredentials(uuid, startDay, endDay)
		if clErr != nil {
			m.logger.WarnContext(ctx, "failed to issue call link auth credentials",
				slog.String("error", clErr.Error()),
			)
			// Non-fatal: still return group credentials without call link creds.
		}
	}

	m.logger.DebugContext(ctx, "generated group credentials",
		slog.String("uuid", uuid),
		slog.Int("count", len(credentials)),
		slog.Int("callLinkCount", len(callLinkCreds)),
		slog.Bool("zkgroup", m.authServerSecret != nil),
	)

	return &GroupCredentials{
		Credentials:             credentials,
		CallLinkAuthCredentials: callLinkCreds,
		PNI:                     pni,
	}, nil
}

// GetExpiringProfileKeyCredential issues an ExpiringProfileKeyCredential for
// the given account. The credentialRequest is the fully-constructed
// ProfileKeyCredentialRequest from the client (obtained via
// CreateProfileKeyCredentialRequestContext on the client side). The commitment
// is the stored ProfileKeyCommitment for the requested profile version.
//
// When authServerSecret is not configured, a structured stub response is
// returned with the correct wire shape but no cryptographic proof; callers
// should check whether zkgroup is active before relying on the credential.
func (m *CertificatesManager) GetExpiringProfileKeyCredential(
	ctx context.Context,
	aciUUID string,
	credentialRequest *zkgroup.ProfileKeyCredentialRequest,
	commitment *zkgroup.ProfileKeyCommitment,
	credentialExpirationTime zkgroup.Timestamp,
) (*ExpiringProfileKeyCredentialResponse, error) {
	if m.authServerSecret == nil {
		// Return a structured stub when zkgroup is not configured so the REST
		// handler can still return a well-formed response.
		m.logger.WarnContext(ctx, "issuing stub profile key credential: authServerSecret not configured",
			slog.String("aci", aciUUID),
		)
		return m.stubProfileKeyCredential(ctx, aciUUID, credentialExpirationTime)
	}

	parsed, err := uuid.Parse(aciUUID)
	if err != nil {
		return nil, &InvalidUUIDError{Value: aciUUID, Cause: err}
	}
	var uuidBytes [16]byte
	copy(uuidBytes[:], parsed[:])
	aci := zkgroup.NewACI(uuidBytes)

	var randomness zkgroup.RandomnessBytes
	if _, err := randRead(randomness[:]); err != nil {
		return nil, &CertificateGenerationError{Operation: "profile-key-randomness", Cause: err}
	}

	response, err := m.authServerSecret.IssueExpiringProfileKeyCredential(
		randomness,
		credentialRequest,
		aci,
		commitment,
		credentialExpirationTime,
	)
	if err != nil {
		return nil, &ZKGroupError{Operation: "issue-expiring-profile-key-credential", Cause: err}
	}

	// Serialize the full response (reserved + blinded credential + expiration +
	// proof) to the Rust wire format the client expects in
	// ReceiveExpiringProfileKeyCredential.
	credBytes := zkgroup.SerializeExpiringProfileKeyCredentialResponse(response)

	m.logger.DebugContext(ctx, "issued expiring profile key credential",
		slog.String("aci", aciUUID),
		slog.Uint64("expirationTime", credentialExpirationTime.EpochSeconds()),
	)

	return &ExpiringProfileKeyCredentialResponse{
		Credential:               credBytes,
		CredentialExpirationTime: int64(credentialExpirationTime.EpochSeconds()),
	}, nil
}

// GetExpiringProfileKeyCredentialStub returns a structured stub
// ExpiringProfileKeyCredentialResponse for the given ACI. This is used
// when the full zkgroup credential request cannot be deserialized (because
// the wire format deserializer is not yet implemented in go-libsignal), or
// when authServerSecret is not configured. The stub has the correct wire
// shape so that the REST handler can return a well-formed response.
func (m *CertificatesManager) GetExpiringProfileKeyCredentialStub(
	ctx context.Context,
	aciUUID string,
	credentialExpirationTime zkgroup.Timestamp,
) (*ExpiringProfileKeyCredentialResponse, error) {
	m.logger.WarnContext(ctx, "issuing stub profile key credential",
		slog.String("aci", aciUUID),
		slog.String("reason", "ProfileKeyCredentialRequest wire deserialization not yet available"),
	)
	return m.stubProfileKeyCredential(ctx, aciUUID, credentialExpirationTime)
}

// signCertificate signs the sender certificate fields. When an Ed25519 private
// key is configured, the canonical JSON payload is signed with Ed25519
// (producing a 64-byte signature). Otherwise HMAC-SHA256 is used as a fallback
// (producing a 32-byte MAC). The Signer field of the certificate is not
// included in the signed payload to avoid circular dependency.
func (m *CertificatesManager) signCertificate(ctx context.Context, cert *SenderCertificate) ([]byte, error) {
	// Create a signing payload without the signer field to avoid circular
	// dependency in the signature.
	payload := struct {
		SenderUUID     string `json:"senderUuid"`
		SenderE164     string `json:"senderE164,omitempty"`
		SenderDeviceID uint32 `json:"senderDeviceId"`
		Expiration     int64  `json:"expiration"`
		IdentityKey    []byte `json:"identityKey"`
	}{
		SenderUUID:     cert.SenderUUID,
		SenderE164:     cert.SenderE164,
		SenderDeviceID: cert.SenderDeviceID,
		Expiration:     cert.Expiration,
		IdentityKey:    cert.IdentityKey,
	}

	data, err := jsonMarshal(payload)
	if err != nil {
		return nil, err
	}

	var sig []byte
	configured, err := m.useEd25519Key(ctx, func(priv ed25519.PrivateKey) error {
		sig = ed25519.Sign(priv, data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if configured {
		return sig, nil
	}

	// HMAC-SHA256 fallback for backwards compatibility.
	return m.hmacSHA256(ctx, data)
}

// hmacSHA256 signs data with the legacy HMAC key inside the key's own borrow,
// so the key never leaves protected memory. A key that is not configured or
// cannot be opened is *HMACKeyError: signing under an empty key would produce
// a credential anyone can recompute.
func (m *CertificatesManager) hmacSHA256(ctx context.Context, data []byte) ([]byte, error) {
	var sum []byte
	if err := m.signingKey.TryWithBytes(ctx, func(key []byte) {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		sum = mac.Sum(nil)
	}); err != nil {
		return nil, &HMACKeyError{Cause: err}
	}
	return sum, nil
}

// issueAuthCredentialWithPni issues a zkgroup AuthCredentialWithPniZkc for the
// given account at the specified redemption time. The credential encodes the
// ACI and PNI together with a zero-knowledge proof.
func (m *CertificatesManager) issueAuthCredentialWithPni(
	aciUUID string,
	pniStr string,
	redemptionTime int64,
) ([]byte, error) {
	aciParsed, err := uuid.Parse(aciUUID)
	if err != nil {
		return nil, &InvalidUUIDError{Value: aciUUID, Cause: err}
	}
	var aciBytes [16]byte
	copy(aciBytes[:], aciParsed[:])
	aci := zkgroup.NewACI(aciBytes)

	// Derive PNI UUID bytes. The PNI may arrive as "PNI:<uuid>" or bare uuid.
	pniRaw := pniStr
	const pniPrefix = "PNI:"
	if len(pniRaw) > len(pniPrefix) && pniRaw[:len(pniPrefix)] == pniPrefix {
		pniRaw = pniRaw[len(pniPrefix):]
	}
	pniParsed, err := uuid.Parse(pniRaw)
	if err != nil {
		// Fall back to using the ACI bytes as a synthetic PNI when parsing
		// fails; the PNI string is caller-supplied and may be opaque.
		pniParsed = aciParsed
	}
	var pniBytes [16]byte
	copy(pniBytes[:], pniParsed[:])
	pni := zkgroup.NewPNI(pniBytes)

	timestamp := zkgroup.NewTimestamp(uint64(redemptionTime))

	var randomness zkgroup.RandomnessBytes
	if _, err := randRead(randomness[:]); err != nil {
		return nil, err
	}

	response, err := m.authServerSecret.IssueAuthCredentialWithPniZkc(aci, pni, timestamp, randomness)
	if err != nil {
		return nil, &ZKGroupError{Operation: "issue-auth-credential-with-pni", Cause: err}
	}

	// Serialize the proof using zkcredential's encoder wrapped with the
	// zkgroup reserved-byte prefix for wire compatibility.
	return zkgroup.Serialize(zkcredential.EncodeIssuanceProof(response.Proof)), nil
}

// issueCallLinkAuthCredentials issues CallLinkAuthCredentials for each day
// in the given range using zkgroup.
func (m *CertificatesManager) issueCallLinkAuthCredentials(accountUUID string, startDay, endDay int64) ([]CallLinkAuthCredential, error) {
	parsed, err := uuid.Parse(accountUUID)
	if err != nil {
		return nil, err
	}

	var uuidBytes [16]byte
	copy(uuidBytes[:], parsed[:])
	userID := zkgroup.NewACI(uuidBytes)

	creds := make([]CallLinkAuthCredential, 0, endDay-startDay+1)

	for day := startDay; day <= endDay; day++ {
		redemptionTime := day * secondsPerDay
		timestamp := zkgroup.NewTimestamp(uint64(redemptionTime))

		var randomness zkgroup.RandomnessBytes
		if _, err := randRead(randomness[:]); err != nil {
			return nil, err
		}

		response, err := zkgroup.IssueCallLinkAuthCredential(userID, timestamp, m.callingZKParams, randomness)
		if err != nil {
			return nil, err
		}

		credential := zkgroup.Serialize(zkcredential.EncodeIssuanceProof(response.Proof))

		creds = append(creds, CallLinkAuthCredential{
			Credential:     credential,
			RedemptionTime: redemptionTime,
		})
	}

	return creds, nil
}

// generateGroupCredential produces an HMAC-SHA256 credential binding the
// account UUID to a specific redemption time. This is the fallback path used
// when authServerSecret is not configured.
func (m *CertificatesManager) generateGroupCredential(ctx context.Context, uuid string, redemptionTime int64) ([]byte, error) {
	payload := struct {
		UUID           string `json:"uuid"`
		RedemptionTime int64  `json:"redemptionTime"`
	}{
		UUID:           uuid,
		RedemptionTime: redemptionTime,
	}

	data, err := jsonMarshal(payload)
	if err != nil {
		return nil, err
	}

	return m.hmacSHA256(ctx, data)
}

// stubProfileKeyCredential returns a structured stub ExpiringProfileKeyCredential
// response when the full zkgroup server secret is not configured. The stub
// uses HMAC-SHA256 over the UUID and expiration to produce a deterministic
// placeholder credential that has the correct wire shape.
func (m *CertificatesManager) stubProfileKeyCredential(
	ctx context.Context,
	aciUUID string,
	credentialExpirationTime zkgroup.Timestamp,
) (*ExpiringProfileKeyCredentialResponse, error) {
	payload := struct {
		ACI            string `json:"aci"`
		ExpirationTime uint64 `json:"expirationTime"`
	}{
		ACI:            aciUUID,
		ExpirationTime: credentialExpirationTime.EpochSeconds(),
	}

	data, err := jsonMarshal(payload)
	if err != nil {
		return nil, &CertificateGenerationError{Operation: "stub-profile-key-credential", Cause: err}
	}

	credBytes, err := m.hmacSHA256(ctx, data)
	if err != nil {
		return nil, err
	}

	return &ExpiringProfileKeyCredentialResponse{
		Credential:               credBytes,
		CredentialExpirationTime: int64(credentialExpirationTime.EpochSeconds()),
	}, nil
}

// invalidKeyLengthError reports an invalid key length.
type invalidKeyLengthError struct {
	Got  int
	Want int
}

func (e *invalidKeyLengthError) Error() string {
	return "invalid key length: got " + itoa(e.Got) + ", want " + itoa(e.Want)
}

// itoa converts an int to a decimal string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
