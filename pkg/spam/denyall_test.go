package spam

import (
	"context"
	"testing"
)

func TestDenyAllChecker_BlocksEveryMessage(t *testing.T) {
	c := DenyAllChecker{}
	for _, ctx := range []*CheckContext{nil, {MessageType: 1}, {SenderUUID: "u"}} {
		res, err := c.Check(context.Background(), ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != SpamCheckBlock {
			t.Errorf("expected SpamCheckBlock, got %v", res)
		}
	}
}

func TestDenyAllFraudChecker_BlocksEveryRegistration(t *testing.T) {
	c := DenyAllFraudChecker{}
	for _, req := range []*RegistrationFraudRequest{nil, {IP: "1.2.3.4"}, {PhoneNumber: "+15551234567"}} {
		if !c.Check(context.Background(), req) {
			t.Errorf("expected DenyAllFraudChecker to block, got allow for %+v", req)
		}
	}
}
