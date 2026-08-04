//go:build integration

package mocks

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// --- TwilioMock --------------------------------------------------------

func TestTwilioMock_SendAndCheck(t *testing.T) {
	m := NewTwilioMock()
	t.Cleanup(m.Close)

	// "Send code" via the /Verifications endpoint.
	resp, err := http.Post(m.URL()+"/Services/VAtest/Verifications", "application/x-www-form-urlencoded",
		strings.NewReader("To=%2B15551234567&Channel=sms"))
	if err != nil {
		t.Fatalf("POST Verifications: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	to, channel, code := m.LastSend()
	if to != "+15551234567" || channel != "sms" || code == "" {
		t.Errorf("LastSend = (%q, %q, %q)", to, channel, code)
	}

	// "Submit code" — pending before Approve.
	resp, _ = http.Post(m.URL()+"/Services/VAtest/VerificationCheck", "application/x-www-form-urlencoded",
		strings.NewReader("To=%2B15551234567&Code=123456"))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte(`"status":"pending"`)) {
		t.Errorf("expected pending, got %s", body)
	}

	// Approve and retry — must now report approved.
	m.Approve("+15551234567", "123456")
	resp, _ = http.Post(m.URL()+"/Services/VAtest/VerificationCheck", "application/x-www-form-urlencoded",
		strings.NewReader("To=%2B15551234567&Code=123456"))
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte(`"status":"approved"`)) {
		t.Errorf("expected approved after Approve, got %s", body)
	}
}

func TestTwilioMock_NextResponseOverridesStatus(t *testing.T) {
	m := NewTwilioMock()
	t.Cleanup(m.Close)
	m.SetNextResponse(http.StatusBadRequest, `{"code":60200,"message":"bad"}`)

	resp, _ := http.Post(m.URL()+"/Services/VAtest/Verifications", "application/x-www-form-urlencoded",
		strings.NewReader("To=%2B1&Channel=sms"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte(`"code":60200`)) {
		t.Errorf("body = %s", body)
	}
}

func TestTwilioMock_UnknownPathReturns404(t *testing.T) {
	m := NewTwilioMock()
	t.Cleanup(m.Close)
	resp, _ := http.Post(m.URL()+"/Services/VAtest/Other", "application/x-www-form-urlencoded", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// --- FCMMock -----------------------------------------------------------

func TestFCMMock_TokenAndSend(t *testing.T) {
	m := NewFCMMock()
	t.Cleanup(m.Close)

	// Token grant.
	resp, err := http.Post(m.TokenURL(), "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=fake"))
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte(`"access_token":"mock-access-token"`)) {
		t.Errorf("token body = %s", body)
	}
	if got := m.TokensIssued(); got != 1 {
		t.Errorf("TokensIssued = %d, want 1", got)
	}

	// Send.
	req, _ := http.NewRequest(http.MethodPost, m.SendURL("test-project"),
		strings.NewReader(`{"message":{"token":"dev-token"}}`))
	req.Header.Set("Authorization", "Bearer mock-access-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST send: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if m.SendsReceived() != 1 {
		t.Errorf("SendsReceived = %d", m.SendsReceived())
	}
	auth, sendBody := m.LastSend()
	if auth != "Bearer mock-access-token" {
		t.Errorf("LastSend.auth = %q", auth)
	}
	if !bytes.Contains(sendBody, []byte("dev-token")) {
		t.Errorf("LastSend.body missing token: %s", sendBody)
	}
}

func TestFCMMock_NextResponseOverrides(t *testing.T) {
	m := NewFCMMock()
	t.Cleanup(m.Close)
	m.SetNextSendResponse(http.StatusNotFound, `{"error":{"status":"NOT_FOUND"}}`)

	req, _ := http.NewRequest(http.MethodPost, m.SendURL("p"), strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer x")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestFCMMock_RejectsNonPostToken(t *testing.T) {
	m := NewFCMMock()
	t.Cleanup(m.Close)
	resp, _ := http.Get(m.TokenURL())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET token, got %d", resp.StatusCode)
	}
}

func TestFCMMock_UnknownSendPathReturns404(t *testing.T) {
	m := NewFCMMock()
	t.Cleanup(m.Close)
	req, _ := http.NewRequest(http.MethodPost, m.Server.URL+"/v1/projects/p/other", nil)
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// --- APNsMock ----------------------------------------------------------

func TestAPNsMock_PushHappyPath(t *testing.T) {
	m := NewAPNsMock()
	t.Cleanup(m.Close)

	req, _ := http.NewRequest(http.MethodPost, m.URL()+"/3/device/devicetoken", strings.NewReader(`{}`))
	req.Header.Set("apns-topic", "com.example.app")
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("apns-collapse-id", "incoming-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if m.PushesReceived() != 1 {
		t.Errorf("PushesReceived = %d", m.PushesReceived())
	}
	tok, topic, pushType, priority, collapse, _ := m.LastPush()
	if tok != "devicetoken" || topic != "com.example.app" || pushType != "alert" ||
		priority != "10" || collapse != "incoming-message" {
		t.Errorf("unexpected headers: tok=%q topic=%q type=%q prio=%q collapse=%q",
			tok, topic, pushType, priority, collapse)
	}
}

func TestAPNsMock_UnregisteredResponse(t *testing.T) {
	m := NewAPNsMock()
	t.Cleanup(m.Close)
	m.SetNextResponse(http.StatusGone, "Unregistered", 1_700_000_000_000)

	req, _ := http.NewRequest(http.MethodPost, m.URL()+"/3/device/stale-token", strings.NewReader(`{}`))
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusGone {
		t.Errorf("expected 410, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte(`"reason":"Unregistered"`)) {
		t.Errorf("expected reason in body, got %s", body)
	}
	if !bytes.Contains(body, []byte(`"timestamp":1700000000000`)) {
		t.Errorf("expected timestamp in body, got %s", body)
	}
}

func TestAPNsMock_RejectsNonPost(t *testing.T) {
	m := NewAPNsMock()
	t.Cleanup(m.Close)
	resp, _ := http.Get(m.URL() + "/3/device/x")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// --- helpers ----------------------------------------------------------

func TestHexPair_HappyPath(t *testing.T) {
	cases := []struct {
		a, b byte
		want byte
		ok   bool
	}{
		{'2', '0', 0x20, true},
		{'a', 'f', 0xaf, true},
		{'A', 'F', 0xaf, true},
		{'g', '0', 0, false},
	}
	for _, c := range cases {
		got, ok := hexPair(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("hexPair(%c,%c) = (%#x, %v); want (%#x, %v)", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

func TestUrlDecode(t *testing.T) {
	cases := map[string]string{
		"plain":      "plain",
		"a+b":        "a b",
		"%2B1":       "+1",
		"%20space":   " space",
		"bad%2":      "bad%2", // truncated escape preserved verbatim
		"bad%ZZbyte": "bad%ZZbyte",
	}
	for in, want := range cases {
		if got := urlDecode(in); got != want {
			t.Errorf("urlDecode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestItoa64(t *testing.T) {
	cases := map[int64]string{
		0:    "0",
		1:    "1",
		-1:   "-1",
		1234: "1234",
		-42:  "-42",
	}
	for in, want := range cases {
		if got := itoa64(in); got != want {
			t.Errorf("itoa64(%d) = %q, want %q", in, got, want)
		}
	}
}
