//go:build integration

package api

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/stretchr/testify/require"
)

// Profile fields are encrypted blobs the server validates to exact byte sizes
// (matching Java @ExactlySize). These helpers produce correctly-sized,
// base64-encoded values so profile PUTs pass validation.
func validProfileName() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 81))
}

func validProfileAbout() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 156))
}

func validProfileEmoji() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 60))
}

func validProfileCommitment() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 97))
}

// profileCredentialReqAndCommitment produces a hex-encoded, wire-valid
// ProfileKeyCredentialRequest for aciUUID together with the matching
// base64-encoded ProfileKeyCommitment, so the credential endpoint can issue a
// credential the request actually satisfies.
func profileCredentialReqAndCommitment(t *testing.T, aciUUID string) (reqHex, commitmentB64 string) {
	t.Helper()
	var rnd zkgroup.RandomnessBytes
	for i := range rnd {
		rnd[i] = byte(i + 1)
	}
	serverSecret, err := zkgroup.GenerateServerSecretParams(rnd)
	require.NoError(t, err)
	serverPublic := serverSecret.GetPublicParams()

	parsed, err := uuid.Parse(aciUUID)
	require.NoError(t, err)
	var aciBytes [16]byte
	copy(aciBytes[:], parsed[:])
	aci := zkgroup.NewACI(aciBytes)

	var pk zkgroup.ProfileKeyBytes
	for i := range pk {
		pk[i] = byte(i + 2)
	}
	profileKey := zkgroup.NewProfileKey(pk)

	var reqRnd zkgroup.RandomnessBytes
	for i := range reqRnd {
		reqRnd[i] = byte(i + 20)
	}
	ctx, err := serverPublic.CreateProfileKeyCredentialRequestContext(reqRnd, aci, profileKey)
	require.NoError(t, err)

	reqBytes := zkgroup.SerializeProfileKeyCredentialRequest(ctx.GetRequest())
	commitBytes := zkgroup.SerializeProfileKeyCommitment(profileKey.GetCommitment(aci))
	return hex.EncodeToString(reqBytes), base64.StdEncoding.EncodeToString(commitBytes)
}
