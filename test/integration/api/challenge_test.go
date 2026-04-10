//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChallenge_SubmitCaptcha(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	challengeResp := map[string]any{
		"type":    "captcha",
		"token":   "test-token-12345",
		"captcha": "test-captcha-solution",
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/challenge", challengeResp, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestChallenge_SubmitPushChallenge(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	challengeResp := map[string]any{
		"type":  "rateLimitPushChallenge",
		"token": "test-push-token-12345",
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/challenge", challengeResp, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestChallenge_SubmitWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	challengeResp := map[string]any{
		"type":    "captcha",
		"token":   "test-token",
		"captcha": "test-captcha",
	}

	resp := env.doRequest(t, "PUT", "/v1/challenge", challengeResp, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestChallenge_RequestPushChallenge(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "POST", "/v1/challenge/push", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestChallenge_RequestPushChallengeWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "POST", "/v1/challenge/push", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestChallenge_SubmitInvalidType(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	challengeResp := map[string]any{
		"type":  "invalid-type",
		"token": "test-token",
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/challenge", challengeResp, uuid, "pass123")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}
