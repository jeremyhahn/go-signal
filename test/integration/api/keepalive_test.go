//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeepalive_HealthCheck(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v1/keepalive", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	decodeJSON(t, resp, &body)
	assert.Equal(t, "ok", body["status"])
}

func TestKeepalive_Provisioning(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v1/keepalive/provisioning", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	decodeJSON(t, resp, &body)
	assert.Equal(t, "ok", body["status"])
}
