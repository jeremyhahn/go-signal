//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testCaptchaSolution is a captcha submission in the dotted format the
// server's Checker requires — provider.sitekey.action.token — matching the
// shape a real client sends. The token slot carries the prefix the test
// provider accepts.
const testCaptchaSolution = "test.testkey.challenge.test-captcha-solution"

func TestChallenge_SubmitCaptcha(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	challengeResp := map[string]any{
		"type":    "captcha",
		"token":   "test-token-12345",
		"captcha": testCaptchaSolution,
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
		"captcha": testCaptchaSolution,
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
