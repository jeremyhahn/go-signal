package certificates

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
)

// TestGetExpiringProfileKeyCredential_ClientCanReceive exercises the full
// server-side issuance path with a real zkgroup secret: a client-created
// request is issued, the serialized response is deserialized, and the client
// successfully receives (unblinds) the credential. This validates both the
// manager's use of SerializeExpiringProfileKeyCredentialResponse and the
// go-libsignal request/commitment/response wire encodings end-to-end.
func TestGetExpiringProfileKeyCredential_ClientCanReceive(t *testing.T) {
	var rnd zkgroup.RandomnessBytes
	for i := range rnd {
		rnd[i] = byte(i + 7)
	}
	secret, err := zkgroup.GenerateServerSecretParams(rnd)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	public := secret.GetPublicParams()

	m := newTestManager([]byte("test-signing-key-0123456789abcd!"))
	m.SetAuthServerSecret(secret)

	aciStr := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	parsed, err := uuid.Parse(aciStr)
	if err != nil {
		t.Fatalf("parse aci: %v", err)
	}
	var aciBytes [16]byte
	copy(aciBytes[:], parsed[:])
	aci := zkgroup.NewACI(aciBytes)

	var pk zkgroup.ProfileKeyBytes
	for i := range pk {
		pk[i] = byte(i + 3)
	}
	profileKey := zkgroup.NewProfileKey(pk)

	var reqRnd zkgroup.RandomnessBytes
	for i := range reqRnd {
		reqRnd[i] = byte(i + 11)
	}
	clientCtx, err := public.CreateProfileKeyCredentialRequestContext(reqRnd, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}
	request := clientCtx.GetRequest()
	commitment := profileKey.GetCommitment(aci)

	currentTime := zkgroup.NewTimestamp(zkgroup.SecondsPerDay * 100)
	expiration := zkgroup.NewTimestamp(zkgroup.SecondsPerDay * 103)

	resp, err := m.GetExpiringProfileKeyCredential(context.Background(), aciStr, request, commitment, expiration)
	if err != nil {
		t.Fatalf("GetExpiringProfileKeyCredential: %v", err)
	}

	decoded, err := zkgroup.DeserializeExpiringProfileKeyCredentialResponse(resp.Credential)
	if err != nil {
		t.Fatalf("DeserializeExpiringProfileKeyCredentialResponse: %v", err)
	}

	cred, err := public.ReceiveExpiringProfileKeyCredential(clientCtx, decoded, currentTime)
	if err != nil {
		t.Fatalf("client could not receive issued credential: %v", err)
	}
	if cred.GetExpirationTime() != expiration {
		t.Errorf("expiration mismatch: got %d want %d", cred.GetExpirationTime().EpochSeconds(), expiration.EpochSeconds())
	}
	if cred.ACIBytes != aciBytes {
		t.Error("ACI mismatch in received credential")
	}
}

// TestGetExpiringProfileKeyCredential_WrongCommitmentFails confirms the
// issuance fails closed when the request does not match the commitment.
func TestGetExpiringProfileKeyCredential_WrongCommitmentFails(t *testing.T) {
	var rnd zkgroup.RandomnessBytes
	for i := range rnd {
		rnd[i] = byte(i + 7)
	}
	secret, err := zkgroup.GenerateServerSecretParams(rnd)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	public := secret.GetPublicParams()

	m := newTestManager([]byte("test-signing-key-0123456789abcd!"))
	m.SetAuthServerSecret(secret)

	aciStr := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	parsed, _ := uuid.Parse(aciStr)
	var aciBytes [16]byte
	copy(aciBytes[:], parsed[:])
	aci := zkgroup.NewACI(aciBytes)

	var pk zkgroup.ProfileKeyBytes
	for i := range pk {
		pk[i] = byte(i + 3)
	}
	profileKey := zkgroup.NewProfileKey(pk)

	var reqRnd zkgroup.RandomnessBytes
	for i := range reqRnd {
		reqRnd[i] = byte(i + 11)
	}
	clientCtx, _ := public.CreateProfileKeyCredentialRequestContext(reqRnd, aci, profileKey)
	request := clientCtx.GetRequest()

	// A commitment from a DIFFERENT profile key must not satisfy the request.
	var otherPK zkgroup.ProfileKeyBytes
	for i := range otherPK {
		otherPK[i] = byte(i + 99)
	}
	wrongCommitment := zkgroup.NewProfileKey(otherPK).GetCommitment(aci)

	expiration := zkgroup.NewTimestamp(zkgroup.SecondsPerDay * 103)
	if _, err := m.GetExpiringProfileKeyCredential(context.Background(), aciStr, request, wrongCommitment, expiration); err == nil {
		t.Fatal("expected issuance to fail with a mismatched commitment")
	}
}
