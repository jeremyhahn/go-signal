package service

import (
	"context"

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
}

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
