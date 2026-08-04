// Package services hosts the gRPC server-side implementations of every
// Signal service.
//
// In Phase 1 each type embeds the generated Unimplemented<Name>Server, so
// every RPC returns codes.Unimplemented cleanly. Phase 2 replaces method
// bodies with real delegation to pkg/service interfaces, one service at
// a time.
//
// Every service takes the pkg/service.Service aggregate (or an explicit
// subset) in its constructor. This keeps wiring explicit — we never reach
// into global state.
package services

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accountpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/account"
	backupspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/backups"
	callqualitypb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/call_quality"
	callingpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/calling"
	credentialspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/credentials"
	devicepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/device"
	keyspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keys"
	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
	messagespb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/messages"
	paymentspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/payments"
	profilepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/profile"

	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

// --- Authenticated services -----------------------------------------
//
// These services require a valid account on the request context, placed
// there by interceptors.AuthenticatedUnary.

// AccountService implements AccountsServer.
type AccountService struct {
	accountpb.UnimplementedAccountsServer
	svc *service.SignalService
}

// NewAccountService returns an AccountService backed by svc.
func NewAccountService(svc *service.SignalService) *AccountService {
	return &AccountService{svc: svc}
}

// MessagesService implements MessagesServer.
type MessagesService struct {
	messagespb.UnimplementedMessagesServer
	svc *service.SignalService
}

// NewMessagesService returns a MessagesService backed by svc.
func NewMessagesService(svc *service.SignalService) *MessagesService {
	return &MessagesService{svc: svc}
}

// KeysService implements KeysServer.
type KeysService struct {
	keyspb.UnimplementedKeysServer
	svc *service.SignalService
}

// NewKeysService returns a KeysService backed by svc.
func NewKeysService(svc *service.SignalService) *KeysService {
	return &KeysService{svc: svc}
}

// ProfileService implements ProfileServer.
type ProfileService struct {
	profilepb.UnimplementedProfileServer
	svc *service.SignalService
}

// NewProfileService returns a ProfileService backed by svc.
func NewProfileService(svc *service.SignalService) *ProfileService {
	return &ProfileService{svc: svc}
}

// DevicesService implements DevicesServer.
type DevicesService struct {
	devicepb.UnimplementedDevicesServer
	svc *service.SignalService
}

// NewDevicesService returns a DevicesService backed by svc.
func NewDevicesService(svc *service.SignalService) *DevicesService {
	return &DevicesService{svc: svc}
}

// BackupsService implements BackupsServer.
type BackupsService struct {
	backupspb.UnimplementedBackupsServer
	svc *service.SignalService
}

// NewBackupsService returns a BackupsService backed by svc.
func NewBackupsService(svc *service.SignalService) *BackupsService {
	return &BackupsService{svc: svc}
}

// CallingService implements CallingServer.
type CallingService struct {
	callingpb.UnimplementedCallingServer
	svc *service.SignalService
}

// NewCallingService returns a CallingService backed by svc.
func NewCallingService(svc *service.SignalService) *CallingService {
	return &CallingService{svc: svc}
}

// CallQualityService implements CallQualityServer.
type CallQualityService struct {
	callqualitypb.UnimplementedCallQualityServer
	svc *service.SignalService
}

// NewCallQualityService returns a CallQualityService backed by svc.
func NewCallQualityService(svc *service.SignalService) *CallQualityService {
	return &CallQualityService{svc: svc}
}

// ExternalServiceCredentialsService implements ExternalServiceCredentialsServer.
type ExternalServiceCredentialsService struct {
	credentialspb.UnimplementedExternalServiceCredentialsServer
	svc *service.SignalService
}

// NewExternalServiceCredentialsService returns a credentials service backed by svc.
func NewExternalServiceCredentialsService(svc *service.SignalService) *ExternalServiceCredentialsService {
	return &ExternalServiceCredentialsService{svc: svc}
}

// PaymentsService implements PaymentsServer. Per ADR-0003 payments are
// skipped from the port; every method remains codes.Unimplemented forever.
type PaymentsService struct {
	paymentspb.UnimplementedPaymentsServer
}

// NewPaymentsService returns a PaymentsService. It takes no service
// backend — payments are deliberately unimplemented.
func NewPaymentsService() *PaymentsService {
	return &PaymentsService{}
}

// --- Anonymous services ---------------------------------------------
//
// These services accept requests without Basic credentials; the
// interceptors.AnonymousUnary interceptor enforces the absence of
// credentials so an attacker cannot slip an authenticated-only RPC into
// an anonymous connection.

// AccountsAnonymousService implements AccountsAnonymousServer.
type AccountsAnonymousService struct {
	accountpb.UnimplementedAccountsAnonymousServer
	svc *service.SignalService
}

// NewAccountsAnonymousService returns the anonymous account service.
func NewAccountsAnonymousService(svc *service.SignalService) *AccountsAnonymousService {
	return &AccountsAnonymousService{svc: svc}
}

// MessagesAnonymousService implements MessagesAnonymousServer.
type MessagesAnonymousService struct {
	messagespb.UnimplementedMessagesAnonymousServer
	svc *service.SignalService
}

// NewMessagesAnonymousService returns the anonymous messages service.
func NewMessagesAnonymousService(svc *service.SignalService) *MessagesAnonymousService {
	return &MessagesAnonymousService{svc: svc}
}

// SendMultiRecipientMessage delegates a SealedSender v2 multi-recipient
// payload to the messages service. Mirrors the REST `PUT /v1/messages/
// multi_recipient` endpoint with `Content-Type: application/vnd.signal-
// messenger.mrm`. The shared payload is stored once in the MRM cache; per-
// recipient envelopes reference it. The `urgent` flag is honored; the
// `ephemeral` flag is currently ignored (parity gap with Java that requires
// a separate ephemeral message path; tracked for a follow-up).
func (s *MessagesAnonymousService) SendMultiRecipientMessage(
	ctx context.Context,
	req *messagespb.SendMultiRecipientMessageRequest,
) (*messagespb.SendMultiRecipientMessageResponse, error) {

	if req == nil || req.GetMessage() == nil {
		return nil, status.Error(codes.InvalidArgument, "missing multi-recipient message")
	}

	mrm := req.GetMessage()
	payload := mrm.GetPayload()
	if len(payload) == 0 {
		return nil, status.Error(codes.InvalidArgument, "empty multi-recipient payload")
	}

	result, err := s.svc.Messages.SendMRMBinary(ctx, messages.MRMSendRequest{
		Body:      payload,
		Timestamp: mrm.GetTimestamp(),
		Lookup: func(ctx context.Context, uuidStr string) (*messages.MRMRecipientAccount, error) {
			acct, lookupErr := s.svc.Accounts.Get(ctx, uuidStr)
			if lookupErr != nil {
				return nil, lookupErr
			}
			return &messages.MRMRecipientAccount{UUID: acct.UUID}, nil
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, messages.ErrMRMNoCache):
			return nil, status.Error(codes.Unavailable, "mrm cache not configured")
		case errors.Is(err, messages.ErrMRMNoRecipients):
			return nil, status.Error(codes.InvalidArgument, "no recipients in ciphertext")
		default:
			if strings.Contains(err.Error(), "parse ciphertext") || strings.Contains(err.Error(), "invalid recipient service id") {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	// uuids404 isn't carried in the gRPC response; Java's gRPC analogue
	// returns the same empty-bodied response. Log the count for ops.
	_ = result
	return &messagespb.SendMultiRecipientMessageResponse{}, nil
}

// KeysAnonymousService implements KeysAnonymousServer.
type KeysAnonymousService struct {
	keyspb.UnimplementedKeysAnonymousServer
	svc *service.SignalService
}

// NewKeysAnonymousService returns the anonymous keys service.
func NewKeysAnonymousService(svc *service.SignalService) *KeysAnonymousService {
	return &KeysAnonymousService{svc: svc}
}

// ProfileAnonymousService implements ProfileAnonymousServer.
type ProfileAnonymousService struct {
	profilepb.UnimplementedProfileAnonymousServer
	svc *service.SignalService
}

// NewProfileAnonymousService returns the anonymous profile service.
func NewProfileAnonymousService(svc *service.SignalService) *ProfileAnonymousService {
	return &ProfileAnonymousService{svc: svc}
}

// BackupsAnonymousService implements BackupsAnonymousServer.
type BackupsAnonymousService struct {
	backupspb.UnimplementedBackupsAnonymousServer
	svc *service.SignalService
}

// NewBackupsAnonymousService returns the anonymous backups service.
func NewBackupsAnonymousService(svc *service.SignalService) *BackupsAnonymousService {
	return &BackupsAnonymousService{svc: svc}
}

// ExternalServiceCredentialsAnonymousService implements
// ExternalServiceCredentialsAnonymousServer.
type ExternalServiceCredentialsAnonymousService struct {
	credentialspb.UnimplementedExternalServiceCredentialsAnonymousServer
	svc *service.SignalService
}

// NewExternalServiceCredentialsAnonymousService returns the anonymous
// credentials service.
func NewExternalServiceCredentialsAnonymousService(svc *service.SignalService) *ExternalServiceCredentialsAnonymousService {
	return &ExternalServiceCredentialsAnonymousService{svc: svc}
}

// --- External-infrastructure services -------------------------------
//
// KeyTransparencyQueryService doesn't use the authenticated/anonymous
// split. It is eventually extracted into its own binary in Phase 4.5;
// here it lives inside signald as a stub. RegistrationService was
// extracted to cmd/registration-service in Phase 4.1.

// KeyTransparencyServiceImpl implements KeyTransparencyQueryServiceServer.
type KeyTransparencyServiceImpl struct {
	ktpb.UnimplementedKeyTransparencyQueryServiceServer
	svc *service.SignalService
}

// NewKeyTransparencyService returns a key-transparency service backed by svc.
func NewKeyTransparencyService(svc *service.SignalService) *KeyTransparencyServiceImpl {
	return &KeyTransparencyServiceImpl{svc: svc}
}
