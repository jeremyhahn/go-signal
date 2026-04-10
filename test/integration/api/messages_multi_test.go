//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessages_MultiRecipient(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass2")
	uuid3, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass3")

	// All test accounts are registered with registrationId=1234 (see registerTestAccount).
	multiReq := map[string]any{
		"recipients": []map[string]any{
			{"uuid": uuid2, "deviceIds": []uint64{1}, "registrationIds": []uint32{1234}},
			{"uuid": uuid3, "deviceIds": []uint64{1}, "registrationIds": []uint32{1234}},
		},
		"commonPayload": base64.StdEncoding.EncodeToString([]byte("multi-recipient-payload")),
		"timestamp":     uint64(time.Now().UnixMilli()),
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/messages/multi_recipient", multiReq, uuid1, "pass1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	uuids404, ok := result["uuids404"].([]any)
	require.True(t, ok, "uuids404 should be an array")
	assert.Empty(t, uuids404, "all recipients exist, so uuids404 should be empty")

	// Verify messages were delivered to both recipients.
	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuid2, "pass2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var msgList map[string]any
	decodeJSON(t, resp, &msgList)
	msgs, ok := msgList["messages"].([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(msgs), 1, "uuid2 should have received a message")

	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuid3, "pass3")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &msgList)
	msgs, ok = msgList["messages"].([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(msgs), 1, "uuid3 should have received a message")
}

func TestMessages_MultiRecipientUnknownRecipient(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")

	unknownUUID := "00000000-0000-0000-0000-000000000099"

	multiReq := map[string]any{
		"recipients": []map[string]any{
			{"uuid": unknownUUID, "deviceIds": []uint64{1}, "registrationIds": []uint32{1234}},
		},
		"commonPayload": base64.StdEncoding.EncodeToString([]byte("multi-recipient-payload")),
		"timestamp":     uint64(time.Now().UnixMilli()),
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/messages/multi_recipient", multiReq, uuid1, "pass1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	uuids404, ok := result["uuids404"].([]any)
	require.True(t, ok, "uuids404 should be an array")
	require.Len(t, uuids404, 1, "should have one unknown recipient")
	assert.Equal(t, unknownUUID, uuids404[0])
}

func TestMessages_MultiRecipientWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	multiReq := map[string]any{
		"recipients":    []map[string]any{},
		"commonPayload": base64.StdEncoding.EncodeToString([]byte("payload")),
		"timestamp":     uint64(time.Now().UnixMilli()),
	}
	resp := env.doRequest(t, "PUT", "/v1/messages/multi_recipient", multiReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestMessages_ReportSpam(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass2")

	// Report spam from uuid2 for a specific message GUID. Both the source and
	// messageGuid path parameters must be valid UUIDs per the handler's parseUUID check.
	messageGUID := "11111111-1111-1111-1111-111111111111"
	resp := env.doAuthRequest(t, "POST", "/v1/messages/report/"+uuid2+"/"+messageGUID, nil, uuid1, "pass1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestMessages_ReportSpamWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "POST", "/v1/messages/report/some-source/some-guid", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
