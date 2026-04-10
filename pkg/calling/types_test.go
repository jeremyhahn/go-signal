package calling

import (
	"encoding/json"
	"testing"
)

func TestTurnToken_ZeroValue(t *testing.T) {
	var token TurnToken
	if token.Username != "" {
		t.Errorf("expected empty username, got %q", token.Username)
	}
	if token.Password != "" {
		t.Errorf("expected empty password, got %q", token.Password)
	}
	if token.TTLSeconds != 0 {
		t.Errorf("expected zero TTL, got %d", token.TTLSeconds)
	}
	if token.URLs != nil {
		t.Errorf("expected nil URLs, got %v", token.URLs)
	}
	if token.URLsWithIPs != nil {
		t.Errorf("expected nil URLsWithIPs, got %v", token.URLsWithIPs)
	}
	if token.Hostname != "" {
		t.Errorf("expected empty hostname, got %q", token.Hostname)
	}
}

func TestTurnToken_FieldAssignment(t *testing.T) {
	token := TurnToken{
		Username:    "user1",
		Password:    "pass1",
		TTLSeconds:  3600,
		URLs:        []string{"turn:relay.example.com:3478"},
		URLsWithIPs: []string{"turn:192.0.2.1:3478"},
		Hostname:    "relay.example.com",
	}
	if token.Username != "user1" {
		t.Errorf("got username %q, want %q", token.Username, "user1")
	}
	if token.Password != "pass1" {
		t.Errorf("got password %q, want %q", token.Password, "pass1")
	}
	if token.TTLSeconds != 3600 {
		t.Errorf("got TTL %d, want 3600", token.TTLSeconds)
	}
	if len(token.URLs) != 1 || token.URLs[0] != "turn:relay.example.com:3478" {
		t.Errorf("got URLs %v, want [turn:relay.example.com:3478]", token.URLs)
	}
	if len(token.URLsWithIPs) != 1 || token.URLsWithIPs[0] != "turn:192.0.2.1:3478" {
		t.Errorf("got URLsWithIPs %v, want [turn:192.0.2.1:3478]", token.URLsWithIPs)
	}
	if token.Hostname != "relay.example.com" {
		t.Errorf("got hostname %q, want %q", token.Hostname, "relay.example.com")
	}
}

func TestTurnToken_JSONRoundTrip(t *testing.T) {
	original := TurnToken{
		Username:    "user1",
		Password:    "pass1",
		TTLSeconds:  86400,
		URLs:        []string{"turn:a.com", "turns:b.com"},
		URLsWithIPs: []string{"turn:10.0.0.1:3478"},
		Hostname:    "relay.example.com",
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded TurnToken
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Username != original.Username {
		t.Errorf("username: got %q, want %q", decoded.Username, original.Username)
	}
	if decoded.Password != original.Password {
		t.Errorf("password: got %q, want %q", decoded.Password, original.Password)
	}
	if decoded.TTLSeconds != original.TTLSeconds {
		t.Errorf("ttl: got %d, want %d", decoded.TTLSeconds, original.TTLSeconds)
	}
	if len(decoded.URLs) != len(original.URLs) {
		t.Errorf("URLs len: got %d, want %d", len(decoded.URLs), len(original.URLs))
	}
	if decoded.Hostname != original.Hostname {
		t.Errorf("hostname: got %q, want %q", decoded.Hostname, original.Hostname)
	}
}

func TestTurnToken_JSONOmitsEmptyHostname(t *testing.T) {
	token := TurnToken{
		Username:   "u",
		Password:   "p",
		TTLSeconds: 60,
		URLs:       []string{},
	}
	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal raw: %v", err)
	}
	if _, ok := raw["hostname"]; ok {
		t.Error("expected hostname to be omitted from JSON when empty")
	}
}

func TestGetCallingRelaysResponse_ZeroValue(t *testing.T) {
	var resp GetCallingRelaysResponse
	if resp.Relays != nil {
		t.Errorf("expected nil relays, got %v", resp.Relays)
	}
}

func TestGetCallingRelaysResponse_FieldAssignment(t *testing.T) {
	resp := GetCallingRelaysResponse{
		Relays: []TurnToken{
			{Username: "u1", Password: "p1"},
			{Username: "u2", Password: "p2"},
		},
	}
	if len(resp.Relays) != 2 {
		t.Fatalf("got %d relays, want 2", len(resp.Relays))
	}
	if resp.Relays[0].Username != "u1" {
		t.Errorf("relay[0] username: got %q, want %q", resp.Relays[0].Username, "u1")
	}
	if resp.Relays[1].Username != "u2" {
		t.Errorf("relay[1] username: got %q, want %q", resp.Relays[1].Username, "u2")
	}
}

func TestGetCallingRelaysResponse_JSONRoundTrip(t *testing.T) {
	original := GetCallingRelaysResponse{
		Relays: []TurnToken{
			{Username: "u", Password: "p", TTLSeconds: 100, URLs: []string{"turn:a.com"}},
		},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded GetCallingRelaysResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.Relays) != 1 {
		t.Fatalf("relays len: got %d, want 1", len(decoded.Relays))
	}
	if decoded.Relays[0].Username != "u" {
		t.Errorf("relay username: got %q, want %q", decoded.Relays[0].Username, "u")
	}
}

func TestCreateCallLinkCredentialRequest_ZeroValue(t *testing.T) {
	var req CreateCallLinkCredentialRequest
	if req.CreateCallLinkCredentialRequest != nil {
		t.Errorf("expected nil request bytes, got %v", req.CreateCallLinkCredentialRequest)
	}
}

func TestCreateCallLinkCredentialRequest_FieldAssignment(t *testing.T) {
	req := CreateCallLinkCredentialRequest{
		CreateCallLinkCredentialRequest: []byte{0x01, 0x02, 0x03},
	}
	if len(req.CreateCallLinkCredentialRequest) != 3 {
		t.Errorf("got %d bytes, want 3", len(req.CreateCallLinkCredentialRequest))
	}
}

func TestCreateCallLinkCredentialRequest_JSONRoundTrip(t *testing.T) {
	original := CreateCallLinkCredentialRequest{
		CreateCallLinkCredentialRequest: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded CreateCallLinkCredentialRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.CreateCallLinkCredentialRequest) != len(original.CreateCallLinkCredentialRequest) {
		t.Errorf("bytes len: got %d, want %d",
			len(decoded.CreateCallLinkCredentialRequest),
			len(original.CreateCallLinkCredentialRequest))
	}
	for i, b := range decoded.CreateCallLinkCredentialRequest {
		if b != original.CreateCallLinkCredentialRequest[i] {
			t.Errorf("byte[%d]: got 0x%02X, want 0x%02X", i, b, original.CreateCallLinkCredentialRequest[i])
		}
	}
}

func TestCreateCallLinkCredentialResponse_ZeroValue(t *testing.T) {
	var resp CreateCallLinkCredentialResponse
	if resp.Credential != nil {
		t.Errorf("expected nil credential, got %v", resp.Credential)
	}
	if resp.RedemptionTime != 0 {
		t.Errorf("expected zero redemption time, got %d", resp.RedemptionTime)
	}
}

func TestCreateCallLinkCredentialResponse_FieldAssignment(t *testing.T) {
	resp := CreateCallLinkCredentialResponse{
		Credential:     []byte{0x01, 0x02},
		RedemptionTime: 1710460800,
	}
	if len(resp.Credential) != 2 {
		t.Errorf("got %d credential bytes, want 2", len(resp.Credential))
	}
	if resp.RedemptionTime != 1710460800 {
		t.Errorf("got redemption time %d, want 1710460800", resp.RedemptionTime)
	}
}

func TestCreateCallLinkCredentialResponse_JSONRoundTrip(t *testing.T) {
	original := CreateCallLinkCredentialResponse{
		Credential:     []byte{0xCA, 0xFE},
		RedemptionTime: 1710460800,
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded CreateCallLinkCredentialResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.RedemptionTime != original.RedemptionTime {
		t.Errorf("redemption time: got %d, want %d", decoded.RedemptionTime, original.RedemptionTime)
	}
	if len(decoded.Credential) != len(original.Credential) {
		t.Errorf("credential len: got %d, want %d", len(decoded.Credential), len(original.Credential))
	}
}

func TestCallQualitySurveyRequest_ZeroValue(t *testing.T) {
	var req CallQualitySurveyRequest
	if req.UserSatisfied {
		t.Error("expected false UserSatisfied")
	}
	if req.StartTimestamp != 0 {
		t.Errorf("expected zero StartTimestamp, got %d", req.StartTimestamp)
	}
	if req.EndTimestamp != 0 {
		t.Errorf("expected zero EndTimestamp, got %d", req.EndTimestamp)
	}
	if req.CallType != "" {
		t.Errorf("expected empty CallType, got %q", req.CallType)
	}
	if req.Success {
		t.Error("expected false Success")
	}
	if req.CallEndReason != "" {
		t.Errorf("expected empty CallEndReason, got %q", req.CallEndReason)
	}
	if req.QualityIssues != nil {
		t.Errorf("expected nil QualityIssues, got %v", req.QualityIssues)
	}
	if req.AdditionalNotes != "" {
		t.Errorf("expected empty AdditionalNotes, got %q", req.AdditionalNotes)
	}
	if req.DebugLogURL != "" {
		t.Errorf("expected empty DebugLogURL, got %q", req.DebugLogURL)
	}
}

func TestCallQualitySurveyRequest_FieldAssignment(t *testing.T) {
	req := CallQualitySurveyRequest{
		UserSatisfied:   true,
		StartTimestamp:  1000,
		EndTimestamp:    2000,
		CallType:        "audio",
		Success:         true,
		CallEndReason:   "normal",
		QualityIssues:   []string{"echo", "delay"},
		AdditionalNotes: "test notes",
		DebugLogURL:     "https://debug.example.com/log",
	}
	if !req.UserSatisfied {
		t.Error("expected UserSatisfied true")
	}
	if req.StartTimestamp != 1000 {
		t.Errorf("got StartTimestamp %d, want 1000", req.StartTimestamp)
	}
	if len(req.QualityIssues) != 2 {
		t.Errorf("got %d quality issues, want 2", len(req.QualityIssues))
	}
}

func TestCallQualitySurveyRequest_JSONRoundTrip(t *testing.T) {
	original := CallQualitySurveyRequest{
		UserSatisfied:   true,
		StartTimestamp:  1000,
		EndTimestamp:    2000,
		CallType:        "video",
		Success:         true,
		CallEndReason:   "hangup",
		QualityIssues:   []string{"choppy"},
		AdditionalNotes: "notes here",
		DebugLogURL:     "https://debug.example.com",
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded CallQualitySurveyRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.CallType != original.CallType {
		t.Errorf("callType: got %q, want %q", decoded.CallType, original.CallType)
	}
	if decoded.StartTimestamp != original.StartTimestamp {
		t.Errorf("startTimestamp: got %d, want %d", decoded.StartTimestamp, original.StartTimestamp)
	}
	if decoded.UserSatisfied != original.UserSatisfied {
		t.Errorf("userSatisfied: got %v, want %v", decoded.UserSatisfied, original.UserSatisfied)
	}
	if decoded.DebugLogURL != original.DebugLogURL {
		t.Errorf("debugLogUrl: got %q, want %q", decoded.DebugLogURL, original.DebugLogURL)
	}
}

func TestCallQualitySurveyRequest_JSONOmitsEmptyOptionalFields(t *testing.T) {
	req := CallQualitySurveyRequest{
		StartTimestamp: 1000,
		EndTimestamp:   2000,
		CallType:       "audio",
		CallEndReason:  "hangup",
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal raw: %v", err)
	}
	for _, field := range []string{"callQualityIssues", "additionalIssuesDescription", "debugLogUrl"} {
		if _, ok := raw[field]; ok {
			t.Errorf("expected %q to be omitted from JSON when empty", field)
		}
	}
}

func TestCallQualitySurveyMessage_ZeroValue(t *testing.T) {
	var msg CallQualitySurveyMessage
	if msg.ResponseID != "" {
		t.Errorf("expected empty ResponseID, got %q", msg.ResponseID)
	}
	if msg.SubmissionTime != 0 {
		t.Errorf("expected zero SubmissionTime, got %d", msg.SubmissionTime)
	}
	if msg.ClientPlatform != "" {
		t.Errorf("expected empty ClientPlatform, got %q", msg.ClientPlatform)
	}
	if msg.ClientVersion != "" {
		t.Errorf("expected empty ClientVersion, got %q", msg.ClientVersion)
	}
	if msg.RemoteAddr != "" {
		t.Errorf("expected empty RemoteAddr, got %q", msg.RemoteAddr)
	}
}

func TestCallQualitySurveyMessage_FieldAssignment(t *testing.T) {
	msg := CallQualitySurveyMessage{
		ResponseID:      "resp-1",
		SubmissionTime:  1710460800000,
		UserSatisfied:   true,
		StartTimestamp:  1000,
		EndTimestamp:    2000,
		CallType:        "audio",
		Success:         true,
		CallEndReason:   "normal",
		QualityIssues:   []string{"echo"},
		AdditionalNotes: "notes",
		DebugLogURL:     "https://debug.example.com",
		ClientPlatform:  "android",
		ClientVersion:   "6.0.0",
		RemoteAddr:      "192.168.1.1",
	}
	if msg.ResponseID != "resp-1" {
		t.Errorf("got ResponseID %q, want %q", msg.ResponseID, "resp-1")
	}
	if msg.ClientPlatform != "android" {
		t.Errorf("got ClientPlatform %q, want %q", msg.ClientPlatform, "android")
	}
	if msg.RemoteAddr != "192.168.1.1" {
		t.Errorf("got RemoteAddr %q, want %q", msg.RemoteAddr, "192.168.1.1")
	}
}

func TestCallQualitySurveyMessage_JSONRoundTrip(t *testing.T) {
	original := CallQualitySurveyMessage{
		ResponseID:      "resp-abc",
		SubmissionTime:  1710460800000,
		UserSatisfied:   false,
		StartTimestamp:  5000,
		EndTimestamp:    6000,
		CallType:        "video",
		Success:         false,
		CallEndReason:   "error",
		QualityIssues:   []string{"pixelated", "dropped"},
		AdditionalNotes: "bad call",
		DebugLogURL:     "https://logs.example.com/abc",
		ClientPlatform:  "ios",
		ClientVersion:   "5.1.2",
		RemoteAddr:      "10.0.0.1",
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded CallQualitySurveyMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.ResponseID != original.ResponseID {
		t.Errorf("ResponseID: got %q, want %q", decoded.ResponseID, original.ResponseID)
	}
	if decoded.SubmissionTime != original.SubmissionTime {
		t.Errorf("SubmissionTime: got %d, want %d", decoded.SubmissionTime, original.SubmissionTime)
	}
	if decoded.ClientPlatform != original.ClientPlatform {
		t.Errorf("ClientPlatform: got %q, want %q", decoded.ClientPlatform, original.ClientPlatform)
	}
	if decoded.RemoteAddr != original.RemoteAddr {
		t.Errorf("RemoteAddr: got %q, want %q", decoded.RemoteAddr, original.RemoteAddr)
	}
	if len(decoded.QualityIssues) != 2 {
		t.Errorf("QualityIssues len: got %d, want 2", len(decoded.QualityIssues))
	}
}

func TestCallQualitySurveyMessage_JSONOmitsEmptyOptionalFields(t *testing.T) {
	msg := CallQualitySurveyMessage{
		ResponseID:     "resp-1",
		SubmissionTime: 1000,
		CallType:       "audio",
		CallEndReason:  "normal",
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal raw: %v", err)
	}
	for _, field := range []string{"callQualityIssues", "additionalIssuesDescription", "debugLogUrl", "clientPlatform", "clientVersion", "remoteAddr"} {
		if _, ok := raw[field]; ok {
			t.Errorf("expected %q to be omitted from JSON when empty", field)
		}
	}
}
