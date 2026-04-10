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

func TestMessages_SendAndRetrieve(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass2")

	// Send a message from user1 to user2.
	msgReq := map[string]any{
		"messages": []map[string]any{
			{
				"type":                1,
				"destinationDeviceId": 1,
				"content":             base64.StdEncoding.EncodeToString([]byte("encrypted-message-content")),
				"timestamp":           uint64(time.Now().UnixMilli()),
			},
		},
		"timestamp": uint64(time.Now().UnixMilli()),
		"urgent":    true,
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/messages/"+uuid2, msgReq, uuid1, "pass1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var sendResp map[string]any
	decodeJSON(t, resp, &sendResp)

	// Retrieve messages for user2.
	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuid2, "pass2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var msgList map[string]any
	decodeJSON(t, resp, &msgList)
	msgs, ok := msgList["messages"].([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(msgs), 1)

	// Verify the message has expected fields.
	msg := msgs[0].(map[string]any)
	assert.NotEmpty(t, msg["guid"])
	assert.Equal(t, uuid1, msg["source"])
	assert.NotEmpty(t, msg["content"])
}

func TestMessages_SendToNonexistentUser(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")

	msgReq := map[string]any{
		"messages": []map[string]any{
			{
				"type":                1,
				"destinationDeviceId": 1,
				"content":             "dGVzdA==",
				"timestamp":           uint64(time.Now().UnixMilli()),
			},
		},
		"timestamp": uint64(time.Now().UnixMilli()),
	}

	// Use a valid UUID format for a nonexistent account; the handler returns 400
	// for non-UUID strings before even looking up the account.
	nonexistentUUID := "00000000-0000-0000-0000-000000000000"
	resp := env.doAuthRequest(t, "PUT", "/v1/messages/"+nonexistentUUID, msgReq, uuid1, "pass1")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestMessages_RetrieveWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v1/messages", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestMessages_DeleteMessage(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass2")

	// Send a message.
	msgReq := map[string]any{
		"messages": []map[string]any{{
			"type": 1, "destinationDeviceId": 1,
			"content": "dGVzdA==", "timestamp": uint64(time.Now().UnixMilli()),
		}},
		"timestamp": uint64(time.Now().UnixMilli()),
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/messages/"+uuid2, msgReq, uuid1, "pass1")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Get messages to find the server GUID.
	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuid2, "pass2")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var msgList map[string]any
	decodeJSON(t, resp, &msgList)
	msgs, ok := msgList["messages"].([]any)
	require.True(t, ok)
	require.Len(t, msgs, 1)
	guid := msgs[0].(map[string]any)["guid"].(string)

	// Delete the message.
	resp = env.doAuthRequest(t, "DELETE", "/v1/messages/uuid/"+guid, nil, uuid2, "pass2")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Verify the message is gone.
	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuid2, "pass2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &msgList)
	msgs, ok = msgList["messages"].([]any)
	require.True(t, ok)
	assert.Empty(t, msgs)
}

func TestMessages_SendWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")

	msgReq := map[string]any{
		"messages": []map[string]any{{
			"type": 1, "destinationDeviceId": 1,
			"content": "dGVzdA==", "timestamp": uint64(time.Now().UnixMilli()),
		}},
		"timestamp": uint64(time.Now().UnixMilli()),
	}
	resp := env.doRequest(t, "PUT", "/v1/messages/"+uuid1, msgReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestMessages_MultipleMessages(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass2")

	// Send 3 messages from user1 to user2.
	for i := 0; i < 3; i++ {
		msgReq := map[string]any{
			"messages": []map[string]any{{
				"type": 1, "destinationDeviceId": 1,
				"content":   base64.StdEncoding.EncodeToString([]byte("message-content")),
				"timestamp": uint64(time.Now().UnixMilli()),
			}},
			"timestamp": uint64(time.Now().UnixMilli()),
		}
		resp := env.doAuthRequest(t, "PUT", "/v1/messages/"+uuid2, msgReq, uuid1, "pass1")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// Retrieve all messages.
	resp := env.doAuthRequest(t, "GET", "/v1/messages", nil, uuid2, "pass2")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var msgList map[string]any
	decodeJSON(t, resp, &msgList)
	msgs, ok := msgList["messages"].([]any)
	require.True(t, ok)
	assert.Len(t, msgs, 3)
}
