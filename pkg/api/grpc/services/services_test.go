package services

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	messagespb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/messages"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/service"
	storagememory "github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// emptySvc is a minimal *service.SignalService used by constructor coverage
// tests. The services under test only stash the pointer at construction time;
// they never dereference it for these assertions.
func emptySvc() *service.SignalService {
	return &service.SignalService{}
}

// TestServiceConstructors confirms every New*Service constructor returns a
// non-nil concrete value and stores the supplied *service.SignalService when
// applicable. Each constructor is trivially correct (struct literal), so a
// single batched test is the right shape: it pins the wiring contract
// without forcing per-constructor noise.
func TestServiceConstructors(t *testing.T) {
	svc := emptySvc()

	cases := []struct {
		name string
		got  any
	}{
		{"NewAccountService", NewAccountService(svc)},
		{"NewMessagesService", NewMessagesService(svc)},
		{"NewKeysService", NewKeysService(svc)},
		{"NewProfileService", NewProfileService(svc)},
		{"NewDevicesService", NewDevicesService(svc)},
		{"NewBackupsService", NewBackupsService(svc)},
		{"NewCallingService", NewCallingService(svc)},
		{"NewCallQualityService", NewCallQualityService(svc)},
		{"NewExternalServiceCredentialsService", NewExternalServiceCredentialsService(svc)},
		{"NewPaymentsService", NewPaymentsService()},
		{"NewAccountsAnonymousService", NewAccountsAnonymousService(svc)},
		{"NewMessagesAnonymousService", NewMessagesAnonymousService(svc)},
		{"NewKeysAnonymousService", NewKeysAnonymousService(svc)},
		{"NewProfileAnonymousService", NewProfileAnonymousService(svc)},
		{"NewBackupsAnonymousService", NewBackupsAnonymousService(svc)},
		{"NewExternalServiceCredentialsAnonymousService", NewExternalServiceCredentialsAnonymousService(svc)},
		{"NewKeyTransparencyService", NewKeyTransparencyService(svc)},
	}
	for _, c := range cases {
		if c.got == nil {
			t.Errorf("%s returned nil", c.name)
		}
	}

	// Sanity-check the embedded pointer on a representative authenticated and
	// anonymous service. Constructors that ignore svc (PaymentsService) are
	// skipped here.
	if got := NewAccountService(svc); got.svc != svc {
		t.Error("NewAccountService did not store the supplied SignalService")
	}
	if got := NewMessagesAnonymousService(svc); got.svc != svc {
		t.Error("NewMessagesAnonymousService did not store the supplied SignalService")
	}
}

// TestSendMultiRecipientMessage_NilRequest verifies the InvalidArgument
// guard at the top of the handler.
func TestSendMultiRecipientMessage_NilRequest(t *testing.T) {
	s := NewMessagesAnonymousService(emptySvc())
	_, err := s.SendMultiRecipientMessage(context.Background(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for nil request, got %v", err)
	}
}

// TestSendMultiRecipientMessage_NilMessage covers the nested
// req.GetMessage() == nil branch.
func TestSendMultiRecipientMessage_NilMessage(t *testing.T) {
	s := NewMessagesAnonymousService(emptySvc())
	_, err := s.SendMultiRecipientMessage(context.Background(), &messagespb.SendMultiRecipientMessageRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for nil message, got %v", err)
	}
}

// TestSendMultiRecipientMessage_EmptyPayload covers the second
// InvalidArgument guard (empty payload).
func TestSendMultiRecipientMessage_EmptyPayload(t *testing.T) {
	s := NewMessagesAnonymousService(emptySvc())
	_, err := s.SendMultiRecipientMessage(context.Background(), &messagespb.SendMultiRecipientMessageRequest{
		Message: &messagespb.MultiRecipientMessage{Timestamp: 1},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty payload, got %v", err)
	}
}

// signalSvcWithMessages wires a minimal SignalService with a real
// MessagesManager (no MRM cache). The handler reaches the SendMRMBinary
// call and returns ErrMRMNoCache, which the handler maps to Unavailable.
func signalSvcWithMessages() *service.SignalService {
	store := storagememory.NewMemoryMessageStore()
	mgr := messages.NewMessagesManager(store)
	return &service.SignalService{Messages: service.NewMessageService(mgr)}
}

// TestSendMultiRecipientMessage_NoCacheReturnsUnavailable exercises the
// ErrMRMNoCache branch of the post-SendMRMBinary error switch.
func TestSendMultiRecipientMessage_NoCacheReturnsUnavailable(t *testing.T) {
	s := NewMessagesAnonymousService(signalSvcWithMessages())
	_, err := s.SendMultiRecipientMessage(context.Background(), &messagespb.SendMultiRecipientMessageRequest{
		Message: &messagespb.MultiRecipientMessage{Timestamp: 1, Payload: []byte("any")},
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable from no-cache path, got %v", err)
	}
}
