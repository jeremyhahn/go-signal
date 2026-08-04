package tracing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewStdoutExporter_PanicsOnNilWriter(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil writer")
		}
	}()
	NewStdoutExporter(nil)
}

func TestStdoutExporter_ExportsOneLinePerSpan(t *testing.T) {
	buf := &bytes.Buffer{}
	exp := NewStdoutExporter(buf)
	if err := exp.Export(Span{TraceID: "t1", SpanID: "s1", Name: "a"}); err != nil {
		t.Fatalf("Export 1: %v", err)
	}
	if err := exp.Export(Span{TraceID: "t1", SpanID: "s2", Name: "b"}); err != nil {
		t.Fatalf("Export 2: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	for i, line := range lines {
		var s Span
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Errorf("line[%d] not JSON: %v", i, err)
		}
	}
}

func TestRecorder_NilExporterIsNoOp(t *testing.T) {
	r := NewRecorder(nil)
	ctx, end := r.Start(context.Background(), "noop")
	if ctx == nil {
		t.Fatal("nil ctx returned")
	}
	end(Attr{Key: "ignored", Value: "y"})
	end() // double-end is a no-op
}

func TestRecorder_EmitsSpanWithDuration(t *testing.T) {
	buf := &bytes.Buffer{}
	r := NewRecorder(NewStdoutExporter(buf))
	now := time.Unix(1_700_000_000, 0).UTC()
	r.now = func() time.Time {
		next := now
		now = now.Add(50 * time.Millisecond)
		return next
	}
	_, end := r.Start(context.Background(), "GET /v1/test")
	end(Attr{Key: "http.status", Value: "200"})

	var s Span
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.Name != "GET /v1/test" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.DurationMs != 50 {
		t.Errorf("DurationMs = %d, want 50", s.DurationMs)
	}
	if s.Attributes["http.status"] != "200" {
		t.Errorf("attrs = %v", s.Attributes)
	}
	if s.TraceID == "" || s.SpanID == "" {
		t.Error("trace/span IDs must be populated")
	}
}

func TestRecorder_ChildSpanInheritsParentTrace(t *testing.T) {
	buf := &bytes.Buffer{}
	r := NewRecorder(NewStdoutExporter(buf))

	// Open the parent first.
	parent, _ := New()
	ctx := WithContext(context.Background(), parent)
	ctx, endParent := r.Start(ctx, "parent")
	// Open a child under the parent's context.
	_, endChild := r.Start(ctx, "child")
	endChild(Attr{Key: "k", Value: "v"})
	endParent()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 spans; got %d", len(lines))
	}
	var child Span
	_ = json.Unmarshal([]byte(lines[0]), &child)
	if child.TraceID == "" || child.ParentSpan == "" {
		t.Errorf("child span lacks trace correlation: %+v", child)
	}
}

func TestRecorder_DoubleEndIsIdempotent(t *testing.T) {
	buf := &bytes.Buffer{}
	r := NewRecorder(NewStdoutExporter(buf))
	_, end := r.Start(context.Background(), "x")
	end()
	end()
	if strings.Count(buf.String(), "\n") != 1 {
		t.Errorf("double-end emitted twice; buf=%q", buf.String())
	}
}

func TestStdoutExporter_CloseIsNoOp(t *testing.T) {
	if err := NewStdoutExporter(&bytes.Buffer{}).Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestStdoutExporter_WriteError(t *testing.T) {
	exp := NewStdoutExporter(&failWriter{})
	err := exp.Export(Span{TraceID: "t", SpanID: "s", Name: "n"})
	if err == nil {
		t.Error("expected error when underlying writer fails")
	}
}

// failWriter is an io.Writer that always returns an error.
type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("disk full")
}

func TestRecorder_NilRecorder_IsNoOp(t *testing.T) {
	var r *Recorder
	ctx, end := r.Start(context.Background(), "noop")
	if ctx == nil {
		t.Fatal("nil Recorder.Start returned nil ctx")
	}
	end() // must not panic
}

func TestTraceContextHex(t *testing.T) {
	tc, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(tc.TraceIDHex()) != 32 {
		t.Errorf("TraceIDHex length = %d, want 32", len(tc.TraceIDHex()))
	}
	if len(tc.SpanIDHex()) != 16 {
		t.Errorf("SpanIDHex length = %d, want 16", len(tc.SpanIDHex()))
	}
}
