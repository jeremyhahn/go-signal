//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStickers_GetUploadForm(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/sticker/pack/form/5", nil, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	assert.NotEmpty(t, result["packId"])
	assert.NotNil(t, result["manifest"])

	stickers, ok := result["stickers"].([]any)
	require.True(t, ok)
	assert.Len(t, stickers, 5)
}

func TestStickers_GetUploadFormWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/sticker/pack/form/5", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
