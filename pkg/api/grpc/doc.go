// Package grpc hosts the gRPC surface of go-signal. The package tree is:
//
//   - genproto/     Generated .pb.go and _grpc.pb.go files from pkg/api/grpc/proto/.
//     Regenerate with `make proto`.
//   - proto/        Source .proto files, copied verbatim from Java Signal-Server
//     with only `option go_package` annotations added.
//   - server.go     gRPC server assembly and lifecycle.
//   - interceptors/ Auth + logging + rate-limit interceptors.
//   - services/     Server-side service implementations that delegate to
//     pkg/service interfaces.
//
// In Phase 1 every service is scaffolded with UnimplementedXServer
// embedded, so every RPC returns codes.Unimplemented cleanly. Real logic
// lands as each service is wired up in Phase 2.
package grpc
