// Package tracing carries request-ID + W3C traceparent propagation
// across the Phase 4 binaries. Mobile clients and intermediate
// proxies set the standard `traceparent` header; the chat-server
// parses it, threads the trace + span IDs through the request
// context, and re-emits them on outbound calls.
//
// Wire format follows W3C Trace Context level 1 exactly:
//
//	traceparent: 00-<trace-id-32-hex>-<span-id-16-hex>-<flags-2-hex>
//
// When no traceparent is present (e.g. the request originates from a
// client without tracing support), the middleware mints a fresh
// trace+span pair so downstream services still see a unified
// correlation ID.
//
// This package is deliberately SDK-free — full OpenTelemetry exporter
// wiring lives in a future sub-phase that bumps go.mod to add the
// OTLP / stdout exporters. Until then, structured logs and
// distributed tracing share the trace ID via the context helpers
// defined here.
package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// TraceContext is the parsed traceparent payload.
type TraceContext struct {
	// TraceID is the 16-byte (32 hex) trace identifier shared across
	// all spans of a request.
	TraceID [16]byte
	// SpanID is the 8-byte (16 hex) identifier of the immediate
	// parent span.
	SpanID [8]byte
	// Sampled reports whether the sampled bit in flags is set.
	Sampled bool
}

// HeaderName is the standard W3C traceparent header.
const HeaderName = "traceparent"

// ErrInvalidTraceparent indicates the header value did not match the
// W3C level-1 grammar.
var ErrInvalidTraceparent = errors.New("tracing: invalid traceparent header")

// Parse decodes a W3C traceparent header value.
func Parse(header string) (TraceContext, error) {
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if parts[0] != "00" {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return TraceContext{}, ErrInvalidTraceparent
	}
	var tc TraceContext
	if _, err := hex.Decode(tc.TraceID[:], []byte(parts[1])); err != nil {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if isZero(tc.TraceID[:]) {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if _, err := hex.Decode(tc.SpanID[:], []byte(parts[2])); err != nil {
		return TraceContext{}, ErrInvalidTraceparent
	}
	if isZero(tc.SpanID[:]) {
		return TraceContext{}, ErrInvalidTraceparent
	}
	flags, err := strconv.ParseUint(parts[3], 16, 8)
	if err != nil {
		return TraceContext{}, ErrInvalidTraceparent
	}
	tc.Sampled = flags&0x01 == 0x01
	return tc, nil
}

// Header returns the W3C-format value for the receiving TraceContext.
func (tc TraceContext) Header() string {
	flags := uint8(0)
	if tc.Sampled {
		flags = 1
	}
	var buf strings.Builder
	buf.WriteString("00-")
	buf.WriteString(hex.EncodeToString(tc.TraceID[:]))
	buf.WriteByte('-')
	buf.WriteString(hex.EncodeToString(tc.SpanID[:]))
	buf.WriteByte('-')
	buf.WriteString(hexByte(flags))
	return buf.String()
}

// TraceIDHex returns the 32-character hex form of TraceID.
func (tc TraceContext) TraceIDHex() string { return hex.EncodeToString(tc.TraceID[:]) }

// SpanIDHex returns the 16-character hex form of SpanID.
func (tc TraceContext) SpanIDHex() string { return hex.EncodeToString(tc.SpanID[:]) }

// New mints a fresh TraceContext with random IDs and Sampled=true.
// Used when the inbound request had no traceparent.
func New() (TraceContext, error) {
	var tc TraceContext
	if _, err := rand.Read(tc.TraceID[:]); err != nil {
		return TraceContext{}, err
	}
	if _, err := rand.Read(tc.SpanID[:]); err != nil {
		return TraceContext{}, err
	}
	tc.Sampled = true
	return tc, nil
}

// NewChildSpan returns a TraceContext that keeps tc.TraceID but mints
// a fresh SpanID. Use this when forwarding to a downstream service:
// the trace stays correlated, the span identifies the new call.
func (tc TraceContext) NewChildSpan() (TraceContext, error) {
	out := tc
	if _, err := rand.Read(out.SpanID[:]); err != nil {
		return TraceContext{}, err
	}
	return out, nil
}

type ctxKey struct{}

// WithContext returns ctx with tc attached so handlers can call
// FromContext(ctx) to retrieve the active trace context.
func WithContext(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, ctxKey{}, tc)
}

// FromContext returns the trace context attached to ctx via
// WithContext, plus a bool indicating whether one was present.
func FromContext(ctx context.Context) (TraceContext, bool) {
	v, ok := ctx.Value(ctxKey{}).(TraceContext)
	return v, ok
}

// isZero reports whether every byte in b is 0.
func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// hexByte returns the two-character lower-case hex form of b.
func hexByte(b uint8) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(b>>4)&0xF], digits[b&0xF]})
}
