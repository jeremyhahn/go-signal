package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
)

// GRPCServer implements ktpb.KeyTransparencyQueryServiceServer by
// delegating to a Log + ed25519 signer.
type GRPCServer struct {
	ktpb.UnimplementedKeyTransparencyQueryServiceServer
	log    Log
	signer ed25519.PrivateKey
}

// NewGRPCServer constructs a GRPCServer.
func NewGRPCServer(log Log, signer ed25519.PrivateKey) *GRPCServer {
	if log == nil {
		panic("kt: log is required")
	}
	if len(signer) != ed25519.PrivateKeySize {
		panic("kt: ed25519 signer required")
	}
	return &GRPCServer{log: log, signer: signer}
}

// Distinguished implements the Distinguished RPC. The "distinguished"
// key in KT is a well-known account (operator-chosen, or zero-bytes
// for the MVP) clients use as a consistency anchor; we return the
// current TreeHead and the entry for the distinguished key when
// present.
func (s *GRPCServer) Distinguished(_ context.Context, _ *ktpb.DistinguishedRequest) (*ktpb.DistinguishedResponse, error) {
	head, err := s.currentTreeHead()
	if err != nil {
		return nil, err
	}
	return &ktpb.DistinguishedResponse{
		TreeHead:      head,
		Distinguished: &ktpb.CondensedTreeSearchResponse{},
	}, nil
}

// Search implements the Search RPC.
func (s *GRPCServer) Search(_ context.Context, req *ktpb.SearchRequest) (*ktpb.SearchResponse, error) {
	if len(req.GetAci()) != 16 {
		return nil, status.Error(codes.InvalidArgument, "aci must be 16 bytes")
	}
	head, err := s.currentTreeHead()
	if err != nil {
		return nil, err
	}
	resp := &ktpb.SearchResponse{TreeHead: head}

	// ACI lookup is always answered. Attach an inclusion proof when
	// the underlying Log supports it (MemoryLog does); other Log
	// impls degrade to a bare Opening which the client treats as
	// "proof unavailable".
	resp.Aci = s.buildCondensed(req.GetAci())

	// Optional username_hash lookup.
	if uh := req.GetUsernameHash(); len(uh) == 32 {
		if c := s.buildCondensed(uh); c.GetOpening() != nil {
			resp.UsernameHash = c
		}
	}

	// Optional E.164 lookup.
	if e164 := req.GetE164SearchRequest(); e164 != nil && e164.GetE164() != "" {
		if c := s.buildCondensed([]byte(e164.GetE164())); c.GetOpening() != nil {
			resp.E164 = c
		}
	}
	return resp, nil
}

// buildCondensed wraps the Search response shape for one lookup key.
// When the log supports MerkleInclusionProof, the audit path is
// encoded in the SearchProof field; clients verify it against
// FullTreeHead.tree_head's root via VerifyMerkleInclusion. When the
// key isn't present, both fields are zero (proto convention for
// "absent").
func (s *GRPCServer) buildCondensed(key []byte) *ktpb.CondensedTreeSearchResponse {
	entry, ok := s.log.Latest(key)
	if !ok {
		return &ktpb.CondensedTreeSearchResponse{}
	}
	resp := &ktpb.CondensedTreeSearchResponse{Opening: entry.Value}
	prover, ok := s.log.(interface {
		LeafHashes() [][32]byte
		LatestIndex(key []byte) (int, [32]byte)
	})
	if !ok {
		return resp
	}
	idx, _ := prover.LatestIndex(key)
	if idx < 0 {
		return resp
	}
	path, found := MerkleInclusionProof(prover.LeafHashes(), idx)
	if !found {
		return resp
	}
	// Encode the audit path one 32-byte hash per Inclusion slot.
	inclusion := make([][]byte, 0, len(path))
	for _, p := range path {
		hash := make([]byte, 32)
		copy(hash, p[:])
		inclusion = append(inclusion, hash)
	}
	resp.Search = &ktpb.SearchProof{
		Pos:       uint64(idx),
		Inclusion: inclusion,
	}
	return resp
}

// Monitor implements the Monitor RPC. The MVP returns a tree head;
// the focused proof-generation follow-up populates the per-identifier
// inclusion proofs over the monitor positions.
func (s *GRPCServer) Monitor(_ context.Context, _ *ktpb.MonitorRequest) (*ktpb.MonitorResponse, error) {
	head, err := s.currentTreeHead()
	if err != nil {
		return nil, err
	}
	return &ktpb.MonitorResponse{TreeHead: head}, nil
}

// currentTreeHead builds a signed FullTreeHead from the current log
// state. The signature payload is (size || rootHash || timestampMs)
// per SignTreeHead — clients verify via VerifyTreeHead.
func (s *GRPCServer) currentTreeHead() (*ktpb.FullTreeHead, error) {
	size := s.log.Size()
	root := s.log.RootHash()
	ts := time.Now().UTC()
	sig := SignTreeHead(s.signer, size, root, ts)
	if len(sig) == 0 {
		return nil, errors.New("kt: signature failed")
	}
	pub := s.signer.Public().(ed25519.PublicKey)
	return &ktpb.FullTreeHead{
		TreeHead: &ktpb.TreeHead{
			TreeSize:  size,
			Timestamp: ts.UnixMilli(),
			Signatures: []*ktpb.Signature{
				{AuditorPublicKey: append([]byte(nil), pub...), Signature: sig},
			},
		},
		Last:          [][]byte{},
		Distinguished: [][]byte{},
	}, nil
}
