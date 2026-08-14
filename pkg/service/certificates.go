package service

import (
	"context"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/certificates"
)

// CertificateService defines the certificate operations exposed to protocol
// handlers.
type CertificateService interface {
	// GetDeliveryCertificate generates a signed delivery certificate for
	// sealed-sender messaging.
	GetDeliveryCertificate(
		ctx context.Context,
		uuid string,
		e164 string,
		deviceID uint32,
		identityKey []byte,
		includeE164 bool,
	) (*certificates.DeliveryCertificate, error)

	// GetGroupCredentials generates daily group send credentials for an
	// account over the specified time window.
	GetGroupCredentials(
		ctx context.Context,
		uuid string,
		pni string,
		startSeconds int64,
		endSeconds int64,
	) (*certificates.GroupCredentials, error)

	// GetExpiringProfileKeyCredential issues an ExpiringProfileKeyCredential
	// for the given account using the supplied zkgroup credential request and
	// profile-key commitment.
	GetExpiringProfileKeyCredential(
		ctx context.Context,
		aciUUID string,
		credentialRequest *zkgroup.ProfileKeyCredentialRequest,
		commitment *zkgroup.ProfileKeyCommitment,
		credentialExpirationTime zkgroup.Timestamp,
	) (*certificates.ExpiringProfileKeyCredentialResponse, error)

	// GetExpiringProfileKeyCredentialStub returns a structured stub
	// ExpiringProfileKeyCredentialResponse when the full zkgroup request
	// cannot be deserialized or authServerSecret is not configured.
	GetExpiringProfileKeyCredentialStub(
		ctx context.Context,
		aciUUID string,
		credentialExpirationTime zkgroup.Timestamp,
	) (*certificates.ExpiringProfileKeyCredentialResponse, error)
}

// Compile-time assertion: CertificatesManager must satisfy CertificateService.
var _ CertificateService = (*certificates.CertificatesManager)(nil)

// certificateService is the default CertificateService backed by a
// CertificatesManager.
type certificateService struct {
	manager *certificates.CertificatesManager
}

// NewCertificateService returns a CertificateService that delegates to the
// given CertificatesManager. The manager must not be nil.
func NewCertificateService(manager *certificates.CertificatesManager) CertificateService {
	return &certificateService{manager: manager}
}

func (s *certificateService) GetDeliveryCertificate(
	ctx context.Context,
	uuid string,
	e164 string,
	deviceID uint32,
	identityKey []byte,
	includeE164 bool,
) (*certificates.DeliveryCertificate, error) {
	//nolint:staticcheck // Deliberate delegation: this service method is the compatibility surface for the retained CertificatesManager.GetDeliveryCertificate and is removed together with it.
	return s.manager.GetDeliveryCertificate(ctx, uuid, e164, deviceID, identityKey, includeE164)
}

func (s *certificateService) GetGroupCredentials(
	ctx context.Context,
	uuid string,
	pni string,
	startSeconds int64,
	endSeconds int64,
) (*certificates.GroupCredentials, error) {
	return s.manager.GetGroupCredentials(ctx, uuid, pni, startSeconds, endSeconds)
}

func (s *certificateService) GetExpiringProfileKeyCredential(
	ctx context.Context,
	aciUUID string,
	credentialRequest *zkgroup.ProfileKeyCredentialRequest,
	commitment *zkgroup.ProfileKeyCommitment,
	credentialExpirationTime zkgroup.Timestamp,
) (*certificates.ExpiringProfileKeyCredentialResponse, error) {
	return s.manager.GetExpiringProfileKeyCredential(ctx, aciUUID, credentialRequest, commitment, credentialExpirationTime)
}

func (s *certificateService) GetExpiringProfileKeyCredentialStub(
	ctx context.Context,
	aciUUID string,
	credentialExpirationTime zkgroup.Timestamp,
) (*certificates.ExpiringProfileKeyCredentialResponse, error) {
	return s.manager.GetExpiringProfileKeyCredentialStub(ctx, aciUUID, credentialExpirationTime)
}
