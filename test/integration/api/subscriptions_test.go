//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubscriptions_GetConfig(t *testing.T) {
	env := setupTestEnv(t)

	// Subscription configuration is not yet implemented; expect 501.
	resp := env.doRequest(t, "GET", "/v1/subscription/configuration", nil, nil)
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	resp.Body.Close()
}

func TestSubscriptions_UpdateSubscriber(t *testing.T) {
	env := setupTestEnv(t)

	// Subscriber management is not yet implemented; expect 501.
	resp := env.doRequest(t, "PUT", "/v1/subscription/sub-123", nil, nil)
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	resp.Body.Close()
}
