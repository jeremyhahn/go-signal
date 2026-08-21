//go:build integration

package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	libsignalusernames "github.com/jeremyhahn/go-libsignal/pkg/usernames"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// usernameEntropyBytes is the fresh randomness per generated nickname. A
// confirmed username hash belongs to one account for the lifetime of the
// server, so uniqueness here has to hold against every account the server
// has ever confirmed — not merely within this process. 10 bytes hex-encode
// to 20 characters, which with the prefix stays inside the 32-character
// nickname limit while leaving collisions out of reach.
const usernameEntropyBytes = 10

// uniqueNickname returns a nickname no run has used before. The per-run
// phoneRunBase deliberately is not reused: it is reduced modulo 10,000, so
// two runs would share a base every ~118 runs by the birthday bound and
// recreate an already-confirmed username.
func uniqueNickname(t *testing.T) string {
	t.Helper()
	var b [usernameEntropyBytes]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err, "rand.Read for nickname")
	return "integtest" + hex.EncodeToString(b[:])
}

// realUsernameHashAndProofForIntegration generates a ZK-verifiable username hash
// and proof through go-libsignal, suitable for driving the confirm endpoint.
// Each call produces a distinct username, so callers never collide with a
// hash confirmed by an earlier test or an earlier run. Returns the 32-byte
// hash (as []byte) and the base64-encoded proof.
func realUsernameHashAndProofForIntegration(t *testing.T) (hash []byte, proofB64 string) {
	t.Helper()
	u, err := libsignalusernames.FromParts(uniqueNickname(t), "01", libsignalusernames.DefaultNicknameLimits())
	require.NoError(t, err, "FromParts")
	h := u.Hash()
	var randomness [32]byte
	_, err = rand.Read(randomness[:])
	require.NoError(t, err, "rand.Read")
	proof, err := u.Proof(randomness)
	require.NoError(t, err, "Proof")
	out := make([]byte, 32)
	copy(out, h[:])
	return out, base64.StdEncoding.EncodeToString(proof)
}

// confirmUsernameHashForAccount reserves and confirms a real username hash for
// the given account via the REST API. It returns the confirmed hash base64-
// encoded so callers can use it in subsequent assertions. Tests that require a
// confirmed username hash (e.g. to set a username link) should call this helper
// first.
func confirmUsernameHashForAccount(t *testing.T, env *testEnv, acctUUID, password string) string {
	t.Helper()
	hash, proofB64 := realUsernameHashAndProofForIntegration(t)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	// Reserve the hash.
	reserveReq := map[string]any{
		"usernameHashes": []string{hashB64},
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/username_hash/reserve", reserveReq, acctUUID, password)
	require.Equal(t, http.StatusOK, resp.StatusCode, "reserve username hash")
	var reserveResp map[string]any
	decodeJSON(t, resp, &reserveResp)
	token, ok := reserveResp["reservationToken"].(string)
	require.True(t, ok, "reservationToken missing from reserve response")

	// Confirm with the real proof and the token from the reserve response.
	confirmReq := map[string]any{
		"usernameHash":     hashB64,
		"reservationToken": token,
		"zkProof":          proofB64,
	}
	resp = env.doAuthRequest(t, "PUT", "/v1/accounts/username_hash/confirm", confirmReq, acctUUID, password)
	require.Equal(t, http.StatusOK, resp.StatusCode, "confirm username hash")
	resp.Body.Close()

	return hashB64
}

func TestUsernames_ReserveAndConfirm(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Generate a real ZK-verifiable username hash and proof. The confirm
	// endpoint verifies the proof before checking the reservation token, so
	// we must supply a real proof to reach the token-validation path.
	hash, proofB64 := realUsernameHashAndProofForIntegration(t)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	// Reserve the hash. Each hash must be exactly 32 bytes when decoded.
	reserveReq := map[string]any{
		"usernameHashes": []string{hashB64},
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/username_hash/reserve", reserveReq, uuid, "pass123")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("reserve failed: %d %s", resp.StatusCode, string(body))
	}

	var reserveResp map[string]any
	decodeJSON(t, resp, &reserveResp)
	selectedHash, ok := reserveResp["usernameHash"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, selectedHash)

	// Confirm with the real proof but a deliberately wrong token. The server
	// verifies the ZK proof first (succeeds), then validates the reservation
	// token (fails with InvalidReservationTokenError) → 409 Conflict.
	confirmReq := map[string]any{
		"usernameHash":     selectedHash,
		"reservationToken": "bad-token-intentionally-wrong",
		"zkProof":          proofB64,
	}
	resp = env.doAuthRequest(t, "PUT", "/v1/accounts/username_hash/confirm", confirmReq, uuid, "pass123")
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_ReserveEmptyHashes(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	reserveReq := map[string]any{
		"usernameHashes": []string{},
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/username_hash/reserve", reserveReq, uuid, "pass123")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_LookupByHash(t *testing.T) {
	env := setupTestEnv(t)

	// Lookup a hash that doesn't exist.
	hashBytes := []byte("nonexistent-hash-padding-needed")
	hashStr := base64.URLEncoding.EncodeToString(hashBytes)

	resp := env.doRequest(t, "GET", "/v1/accounts/username_hash/"+hashStr, nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_LookupByHashNotFound(t *testing.T) {
	env := setupTestEnv(t)

	hashBytes := []byte("another-nonexistent-hash-pad!!!")
	hashStr := base64.URLEncoding.EncodeToString(hashBytes)

	resp := env.doRequest(t, "GET", "/v1/accounts/username_hash/"+hashStr, nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_DeleteHash(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Deleting a username hash when none is set is idempotent: the server
	// returns 204 No Content regardless of whether a hash existed, matching
	// Java Signal-Server's AccountController#deleteUsernameHash which calls
	// clearUsername unconditionally.
	resp := env.doAuthRequest(t, "DELETE", "/v1/accounts/username_hash", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_DeleteHashWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "DELETE", "/v1/accounts/username_hash", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_SetAndLookupLink(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// A confirmed username hash must exist before a link can be published.
	// Java AccountController#setUsernameLink returns 409 Conflict otherwise;
	// the manager enforces the same invariant via HashForUUID.
	confirmUsernameHashForAccount(t, env, uuid, "pass123")

	encryptedValue := base64.StdEncoding.EncodeToString([]byte("encrypted-username-data-padding!"))

	setReq := map[string]any{
		"usernameLinkEncryptedValue": encryptedValue,
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/username_link", setReq, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var setResp map[string]any
	decodeJSON(t, resp, &setResp)
	handle, ok := setResp["usernameLinkHandle"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, handle)

	// Lookup the link by handle.
	resp = env.doRequest(t, "GET", "/v1/accounts/username_link/"+handle, nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var lookupResp map[string]any
	decodeJSON(t, resp, &lookupResp)
	assert.Equal(t, encryptedValue, lookupResp["usernameLinkEncryptedValue"])
}

func TestUsernames_SetLinkEmptyValue(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	setReq := map[string]any{
		"usernameLinkEncryptedValue": "",
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/username_link", setReq, uuid, "pass123")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_DeleteLink(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Confirm a username hash first so SetLink can succeed.
	confirmUsernameHashForAccount(t, env, uuid, "pass123")

	// Set a link.
	encryptedValue := base64.StdEncoding.EncodeToString([]byte("encrypted-username-data-padding!"))
	setReq := map[string]any{
		"usernameLinkEncryptedValue": encryptedValue,
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/username_link", setReq, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var setResp map[string]any
	decodeJSON(t, resp, &setResp)
	handle := setResp["usernameLinkHandle"].(string)

	// Delete the link.
	resp = env.doAuthRequest(t, "DELETE", "/v1/accounts/username_link", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Verify the link is gone.
	resp = env.doRequest(t, "GET", "/v1/accounts/username_link/"+handle, nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_DeleteLinkNotSet(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Deleting a username link when none is set is idempotent: the server
	// returns 204 No Content regardless of whether a link existed, matching
	// Java Signal-Server's AccountController#deleteUsernameLink.
	resp := env.doAuthRequest(t, "DELETE", "/v1/accounts/username_link", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_LookupLinkNotFound(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/accounts/username_link/nonexistent-handle", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_ReserveWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	hash1 := base64.StdEncoding.EncodeToString([]byte("test-username-hash-1-padding!!!"))
	reserveReq := map[string]any{
		"usernameHashes": []string{hash1},
	}
	resp := env.doRequest(t, "PUT", "/v1/accounts/username_hash/reserve", reserveReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestUsernames_SetLinkWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	setReq := map[string]any{
		"usernameLinkEncryptedValue": base64.StdEncoding.EncodeToString([]byte("encrypted-data")),
	}
	resp := env.doRequest(t, "PUT", "/v1/accounts/username_link", setReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
