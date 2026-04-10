package captcha

import (
	"testing"
)

func TestChallengeType_Constants(t *testing.T) {
	tests := []struct {
		name string
		ct   ChallengeType
		want string
	}{
		{"captcha", ChallengeTypeCaptcha, "captcha"},
		{"push", ChallengeTypePush, "rateLimitPushChallenge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.ct) != tt.want {
				t.Errorf("got %q, want %q", string(tt.ct), tt.want)
			}
		})
	}
}

func TestChallengeType_Distinct(t *testing.T) {
	if ChallengeTypeCaptcha == ChallengeTypePush {
		t.Error("challenge types should be distinct")
	}
}

func TestChallengeResponse_ZeroValue(t *testing.T) {
	var resp ChallengeResponse
	if resp.Type != "" {
		t.Errorf("expected empty type, got %q", resp.Type)
	}
	if resp.Token != "" {
		t.Errorf("expected empty token, got %q", resp.Token)
	}
	if resp.Captcha != "" {
		t.Errorf("expected empty captcha, got %q", resp.Captcha)
	}
}

func TestChallengeResponse_Fields(t *testing.T) {
	resp := ChallengeResponse{
		Type:    ChallengeTypeCaptcha,
		Token:   "abc",
		Captcha: "xyz",
	}
	if resp.Type != ChallengeTypeCaptcha {
		t.Errorf("got type %q, want %q", resp.Type, ChallengeTypeCaptcha)
	}
	if resp.Token != "abc" {
		t.Errorf("got token %q, want %q", resp.Token, "abc")
	}
	if resp.Captcha != "xyz" {
		t.Errorf("got captcha %q, want %q", resp.Captcha, "xyz")
	}
}

func TestPushChallengeRequest_ZeroValue(t *testing.T) {
	var req PushChallengeRequest
	if req.Token != "" {
		t.Errorf("expected empty token, got %q", req.Token)
	}
}

func TestPushChallengeRequest_Fields(t *testing.T) {
	req := PushChallengeRequest{Token: "push-token-123"}
	if req.Token != "push-token-123" {
		t.Errorf("got %q, want %q", req.Token, "push-token-123")
	}
}
