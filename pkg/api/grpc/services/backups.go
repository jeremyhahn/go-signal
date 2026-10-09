package services

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"

	backupspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/backups"
	commonpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/common"
	errorspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/errors"
	"github.com/jeremyhahn/go-signal/pkg/api/grpc/interceptors"
	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// failedZkAuth returns the standard FailedZkAuthentication proto, used as
// the failed_authentication outcome on every BackupsAnonymous RPC.
func failedZkAuth() *errorspb.FailedZkAuthentication {
	return &errorspb.FailedZkAuthentication{}
}

// failedPrecondition returns the standard FailedPrecondition proto.
func failedPrecondition() *errorspb.FailedPrecondition {
	return &errorspb.FailedPrecondition{}
}

// authenticateFromSignedPresentation deserializes the SignedPresentation
// field on a request, calls the BackupService authenticator, and returns
// the [*backups.AuthenticatedUser]. On verification failure returns
// (nil, true) so the caller can emit the failed_authentication outcome in
// its oneof response; on any other error returns (nil, false) and a
// gRPC error status the caller should propagate.
func (s *BackupsAnonymousService) authenticateFromSignedPresentation(
	ctx context.Context,
	sp *backupspb.SignedPresentation,
) (user *backups.AuthenticatedUser, failedAuth bool, err error) {
	if s.svc.Backups == nil {
		return nil, false, status.Error(codes.Unimplemented, "backup service not configured")
	}
	if sp == nil {
		return nil, true, nil
	}
	user, authErr := s.svc.Backups.AuthenticateBackupUser(ctx, sp.GetPresentation(), sp.GetPresentationSignature(), "")
	if authErr != nil {
		var zkErr *backups.FailedZkAuthError
		if errors.As(authErr, &zkErr) {
			return nil, true, nil
		}
		return nil, false, status.Error(codes.Internal, authErr.Error())
	}
	return user, false, nil
}

// --- Backups (authenticated) ------------------------------------------------

// SetBackupId implements BackupsServer.
func (s *BackupsService) SetBackupId(
	ctx context.Context,
	req *backupspb.SetBackupIdRequest,
) (*backupspb.SetBackupIdResponse, error) {
	if s.svc.Backups == nil {
		return nil, status.Error(codes.Unimplemented, "backup service not configured")
	}
	acct := interceptors.AccountFromContext(ctx)
	if acct == nil {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	err := s.svc.Backups.SetBackupID(ctx, acct.UUID, 1, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: req.GetMessagesBackupAuthCredentialRequest(),
		MediaBackupAuthCredentialRequest:    req.GetMediaBackupAuthCredentialRequest(),
	})
	if err != nil {
		return nil, backupErrorToGRPC(err)
	}
	return &backupspb.SetBackupIdResponse{}, nil
}

// RedeemReceipt implements BackupsServer.
func (s *BackupsService) RedeemReceipt(
	ctx context.Context,
	req *backupspb.RedeemReceiptRequest,
) (*backupspb.RedeemReceiptResponse, error) {
	if s.svc.Backups == nil {
		return nil, status.Error(codes.Unimplemented, "backup service not configured")
	}
	acct := interceptors.AccountFromContext(ctx)
	if acct == nil {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	err := s.svc.Backups.RedeemReceipt(ctx, acct.UUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: req.GetPresentation(),
	})
	if err != nil {
		var badReceipt *backups.BadReceiptError
		var missingComm *backups.MissingIDCommitmentError
		switch {
		case errors.As(err, &missingComm):
			return &backupspb.RedeemReceiptResponse{
				Outcome: &backupspb.RedeemReceiptResponse_AccountMissingCommitment{AccountMissingCommitment: failedPrecondition()},
			}, nil
		case errors.As(err, &badReceipt):
			return &backupspb.RedeemReceiptResponse{
				Outcome: &backupspb.RedeemReceiptResponse_InvalidReceipt{InvalidReceipt: failedPrecondition()},
			}, nil
		default:
			return nil, backupErrorToGRPC(err)
		}
	}
	return &backupspb.RedeemReceiptResponse{
		Outcome: &backupspb.RedeemReceiptResponse_Success{Success: &emptypb.Empty{}},
	}, nil
}

// GetBackupAuthCredentials implements BackupsServer.
func (s *BackupsService) GetBackupAuthCredentials(
	ctx context.Context,
	req *backupspb.GetBackupAuthCredentialsRequest,
) (*backupspb.GetBackupAuthCredentialsResponse, error) {
	if s.svc.Backups == nil {
		return nil, status.Error(codes.Unimplemented, "backup service not configured")
	}
	acct := interceptors.AccountFromContext(ctx)
	if acct == nil {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	start := time.Unix(req.GetRedemptionStart(), 0).UTC()
	end := time.Unix(req.GetRedemptionStop(), 0).UTC()
	resp, err := s.svc.Backups.GetBackupAuthCredentials(ctx, acct.UUID, start, end)
	if err != nil {
		return nil, backupErrorToGRPC(err)
	}
	creds := &backupspb.GetBackupAuthCredentialsResponse_Credentials{
		MessageCredentials: make(map[int64]*commonpb.ZkCredential),
		MediaCredentials:   make(map[int64]*commonpb.ZkCredential),
	}
	for _, c := range resp.Credentials {
		zk := &commonpb.ZkCredential{
			RedemptionTime: c.RedemptionTime.Unix(),
			Credential:     c.Credential,
		}
		switch c.Type {
		case backups.CredentialTypeMessages:
			creds.MessageCredentials[c.RedemptionTime.Unix()] = zk
		case backups.CredentialTypeMedia:
			creds.MediaCredentials[c.RedemptionTime.Unix()] = zk
		}
	}
	return &backupspb.GetBackupAuthCredentialsResponse{Credentials: creds}, nil
}

// --- BackupsAnonymous -------------------------------------------------------

// SetPublicKey implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) SetPublicKey(
	ctx context.Context,
	req *backupspb.SetPublicKeyRequest,
) (*backupspb.SetPublicKeyResponse, error) {
	if s.svc.Backups == nil {
		return nil, status.Error(codes.Unimplemented, "backup service not configured")
	}
	sp := req.GetSignedPresentation()
	if sp == nil {
		return &backupspb.SetPublicKeyResponse{
			Outcome: &backupspb.SetPublicKeyResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	err := s.svc.Backups.SetPublicKey(ctx, sp.GetPresentation(), sp.GetPresentationSignature(), req.GetPublicKey())
	if err != nil {
		var zkErr *backups.FailedZkAuthError
		var conflict *backups.PublicKeyConflictError
		if errors.As(err, &zkErr) || errors.As(err, &conflict) {
			return &backupspb.SetPublicKeyResponse{
				Outcome: &backupspb.SetPublicKeyResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
			}, nil
		}
		return nil, backupErrorToGRPC(err)
	}
	return &backupspb.SetPublicKeyResponse{
		Outcome: &backupspb.SetPublicKeyResponse_Success{Success: &emptypb.Empty{}},
	}, nil
}

// GetCdnCredentials implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) GetCdnCredentials(
	ctx context.Context,
	req *backupspb.GetCdnCredentialsRequest,
) (*backupspb.GetCdnCredentialsResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.GetCdnCredentialsResponse{
			Outcome: &backupspb.GetCdnCredentialsResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	headers, err := s.svc.Backups.GenerateReadAuth(ctx, user, int(req.GetCdn()))
	if err != nil {
		return nil, backupErrorToGRPC(err)
	}
	return &backupspb.GetCdnCredentialsResponse{
		Outcome: &backupspb.GetCdnCredentialsResponse_CdnCredentials_{
			CdnCredentials: &backupspb.GetCdnCredentialsResponse_CdnCredentials{Headers: headers},
		},
	}, nil
}

// GetSvrBCredentials implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) GetSvrBCredentials(
	ctx context.Context,
	req *backupspb.GetSvrBCredentialsRequest,
) (*backupspb.GetSvrBCredentialsResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.GetSvrBCredentialsResponse{
			Outcome: &backupspb.GetSvrBCredentialsResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	creds, err := s.svc.Backups.GenerateSVRBAuth(ctx, user)
	if err != nil {
		return nil, backupErrorToGRPC(err)
	}
	defer creds.Destroy()
	// Opened only to populate the response message the client is the bearer
	// of. Reveal rather than Plaintext: an unavailable credential is an
	// internal error, not a successful response with an empty password.
	password, err := creds.Password.Reveal(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &backupspb.GetSvrBCredentialsResponse{
		Outcome: &backupspb.GetSvrBCredentialsResponse_SvrbCredentials{
			SvrbCredentials: &backupspb.GetSvrBCredentialsResponse_SvrBCredentials{
				Username: creds.Username,
				Password: password,
			},
		},
	}, nil
}

// GetMessageBackupInfo implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) GetMessageBackupInfo(
	ctx context.Context,
	req *backupspb.GetBackupInfoRequest,
) (*backupspb.GetMessageBackupInfoResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.GetMessageBackupInfoResponse{
			Outcome: &backupspb.GetMessageBackupInfoResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	info, err := s.svc.Backups.BackupInfo(ctx, user)
	if err != nil {
		return nil, backupErrorToGRPC(err)
	}
	return &backupspb.GetMessageBackupInfoResponse{
		Outcome: &backupspb.GetMessageBackupInfoResponse_BackupInfo{
			BackupInfo: &backupspb.GetMessageBackupInfoResponse_MessageBackupInfo{
				BackupDir:  info.BackupDir,
				Cdn:        uint32(info.CDN),
				BackupName: info.MessageBackupKey,
			},
		},
	}, nil
}

// GetMediaBackupInfo implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) GetMediaBackupInfo(
	ctx context.Context,
	req *backupspb.GetBackupInfoRequest,
) (*backupspb.GetMediaBackupInfoResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.GetMediaBackupInfoResponse{
			Outcome: &backupspb.GetMediaBackupInfoResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	info, err := s.svc.Backups.BackupInfo(ctx, user)
	if err != nil {
		return nil, backupErrorToGRPC(err)
	}
	var used uint64
	if info.MediaUsedSpace != nil && *info.MediaUsedSpace > 0 {
		used = uint64(*info.MediaUsedSpace)
	}
	return &backupspb.GetMediaBackupInfoResponse{
		Outcome: &backupspb.GetMediaBackupInfoResponse_BackupInfo{
			BackupInfo: &backupspb.GetMediaBackupInfoResponse_MediaBackupInfo{
				BackupDir: info.BackupDir,
				MediaDir:  info.MediaDir,
				UsedSpace: used,
			},
		},
	}, nil
}

// Refresh implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) Refresh(
	ctx context.Context,
	req *backupspb.RefreshRequest,
) (*backupspb.RefreshResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.RefreshResponse{
			Outcome: &backupspb.RefreshResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	if err := s.svc.Backups.TTLRefresh(ctx, user); err != nil {
		return nil, backupErrorToGRPC(err)
	}
	return &backupspb.RefreshResponse{
		Outcome: &backupspb.RefreshResponse_Success{Success: &emptypb.Empty{}},
	}, nil
}

// GetUploadForm implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) GetUploadForm(
	ctx context.Context,
	req *backupspb.GetUploadFormRequest,
) (*backupspb.GetUploadFormResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.GetUploadFormResponse{
			Outcome: &backupspb.GetUploadFormResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	var (
		descriptor *backups.UploadDescriptor
		dErr       error
	)
	switch req.GetUploadType().(type) {
	case *backupspb.GetUploadFormRequest_Messages:
		descriptor, dErr = s.svc.Backups.CreateMessageBackupUploadDescriptor(ctx, user)
	case *backupspb.GetUploadFormRequest_Media:
		descriptor, dErr = s.svc.Backups.CreateTemporaryAttachmentUploadDescriptor(ctx, user)
	default:
		return nil, status.Error(codes.InvalidArgument, "missing upload_type")
	}
	if dErr != nil {
		return nil, backupErrorToGRPC(dErr)
	}
	return &backupspb.GetUploadFormResponse{
		Outcome: &backupspb.GetUploadFormResponse_UploadForm_{
			UploadForm: &backupspb.GetUploadFormResponse_UploadForm{
				Cdn:                  uint32(descriptor.CDN),
				Key:                  descriptor.Key,
				Headers:              descriptor.Headers,
				SignedUploadLocation: descriptor.SignedUploadLocation,
			},
		},
	}, nil
}

// CopyMedia implements BackupsAnonymousServer (server-streaming).
func (s *BackupsAnonymousService) CopyMedia(
	req *backupspb.CopyMediaRequest,
	stream backupspb.BackupsAnonymous_CopyMediaServer,
) error {
	ctx := stream.Context()
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return err
	}
	if failed {
		return stream.Send(&backupspb.CopyMediaResponse{
			Outcome: &backupspb.CopyMediaResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		})
	}
	params := make([]backups.CopyParameters, 0, len(req.GetItems()))
	for _, item := range req.GetItems() {
		params = append(params, backups.CopyParameters{
			SourceCDN:    int(item.GetSourceAttachmentCdn()),
			SourceKey:    item.GetSourceKey(),
			SourceLength: int(item.GetObjectLength()),
			EncryptionParameters: backups.MediaEncryptionParameters{
				EncryptionKey: item.GetEncryptionKey(),
				MACKey:        item.GetHmacKey(),
			},
			DestinationMediaID: item.GetMediaId(),
		})
	}
	quota, err := s.svc.Backups.GetCopyQuota(ctx, user, params)
	if err != nil {
		return backupErrorToGRPC(err)
	}
	return s.svc.Backups.CopyToBackup(ctx, *quota, func(cr backups.CopyResult) error {
		resp := &backupspb.CopyMediaResponse{MediaId: cr.MediaID}
		switch cr.Outcome {
		case backups.CopyOutcomeSuccess:
			cdn := uint32(0)
			if cr.CDN != nil {
				cdn = uint32(*cr.CDN)
			}
			resp.Outcome = &backupspb.CopyMediaResponse_Success{Success: &backupspb.CopyMediaResponse_CopySuccess{Cdn: cdn}}
		case backups.CopyOutcomeSourceNotFound:
			resp.Outcome = &backupspb.CopyMediaResponse_SourceNotFound_{SourceNotFound: &backupspb.CopyMediaResponse_SourceNotFound{}}
		case backups.CopyOutcomeSourceWrongLength:
			resp.Outcome = &backupspb.CopyMediaResponse_WrongSourceLength_{WrongSourceLength: &backupspb.CopyMediaResponse_WrongSourceLength{}}
		case backups.CopyOutcomeOutOfQuota:
			resp.Outcome = &backupspb.CopyMediaResponse_OutOfSpace_{OutOfSpace: &backupspb.CopyMediaResponse_OutOfSpace{}}
		}
		return stream.Send(resp)
	})
}

// ListMedia implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) ListMedia(
	ctx context.Context,
	req *backupspb.ListMediaRequest,
) (*backupspb.ListMediaResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.ListMediaResponse{
			Outcome: &backupspb.ListMediaResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	var cursor *string
	if req.Cursor != nil {
		c := req.GetCursor()
		cursor = &c
	}
	result, err := s.svc.Backups.ListMedia(ctx, user, cursor, int(req.GetLimit()))
	if err != nil {
		return nil, backupErrorToGRPC(err)
	}
	listResult := &backupspb.ListMediaResponse_ListResult{
		Page:      make([]*backupspb.ListMediaResponse_ListEntry, 0, len(result.Media)),
		BackupDir: user.BackupDir,
		MediaDir:  user.MediaDir,
	}
	for _, m := range result.Media {
		listResult.Page = append(listResult.Page, &backupspb.ListMediaResponse_ListEntry{
			Cdn:     uint32(m.CDN),
			MediaId: m.Key,
			Length:  uint64(m.Length),
		})
	}
	if result.Cursor != nil {
		c := *result.Cursor
		listResult.Cursor = &c
	}
	return &backupspb.ListMediaResponse{
		Outcome: &backupspb.ListMediaResponse_ListResult_{ListResult: listResult},
	}, nil
}

// DeleteMedia implements BackupsAnonymousServer (server-streaming).
func (s *BackupsAnonymousService) DeleteMedia(
	req *backupspb.DeleteMediaRequest,
	stream backupspb.BackupsAnonymous_DeleteMediaServer,
) error {
	ctx := stream.Context()
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return err
	}
	if failed {
		return stream.Send(&backupspb.DeleteMediaResponse{
			Outcome: &backupspb.DeleteMediaResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		})
	}
	descriptors := make([]backups.StorageDescriptor, 0, len(req.GetItems()))
	for _, it := range req.GetItems() {
		descriptors = append(descriptors, backups.StorageDescriptor{
			CDN: int(it.GetCdn()),
			Key: it.GetMediaId(),
		})
	}
	return s.svc.Backups.DeleteMedia(ctx, user, descriptors, func(sd backups.StorageDescriptor) error {
		return stream.Send(&backupspb.DeleteMediaResponse{
			Outcome: &backupspb.DeleteMediaResponse_DeletedItem{
				DeletedItem: &backupspb.DeleteMediaItem{Cdn: uint32(sd.CDN), MediaId: sd.Key},
			},
		})
	})
}

// DeleteAll implements BackupsAnonymousServer.
func (s *BackupsAnonymousService) DeleteAll(
	ctx context.Context,
	req *backupspb.DeleteAllRequest,
) (*backupspb.DeleteAllResponse, error) {
	user, failed, err := s.authenticateFromSignedPresentation(ctx, req.GetSignedPresentation())
	if err != nil {
		return nil, err
	}
	if failed {
		return &backupspb.DeleteAllResponse{
			Outcome: &backupspb.DeleteAllResponse_FailedAuthentication{FailedAuthentication: failedZkAuth()},
		}, nil
	}
	if err := s.svc.Backups.DeleteEntireBackup(ctx, user); err != nil {
		return nil, backupErrorToGRPC(err)
	}
	return &backupspb.DeleteAllResponse{
		Outcome: &backupspb.DeleteAllResponse_Success{Success: &emptypb.Empty{}},
	}, nil
}

// backupErrorToGRPC maps a typed backups error to a gRPC status code.
func backupErrorToGRPC(err error) error {
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
		return status.Error(codes.PermissionDenied, permErr.Error())
	case errors.As(err, &typeErr):
		return status.Error(codes.PermissionDenied, typeErr.Error())
	case errors.As(err, &zkErr):
		return status.Error(codes.Unauthenticated, zkErr.Error())
	case errors.As(err, &conflictErr):
		return status.Error(codes.AlreadyExists, conflictErr.Error())
	case errors.As(err, &notFoundErr):
		return status.Error(codes.NotFound, notFoundErr.Error())
	case errors.As(err, &invArgErr):
		return status.Error(codes.InvalidArgument, invArgErr.Error())
	case errors.As(err, &rateLimErr):
		return status.Error(codes.ResourceExhausted, rateLimErr.Error())
	case errors.As(err, &badReceipt):
		return status.Error(codes.InvalidArgument, badReceipt.Error())
	case errors.As(err, &missingComm):
		return status.Error(codes.FailedPrecondition, missingComm.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
