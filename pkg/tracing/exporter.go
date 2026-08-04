package tracing

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Span is one trace event spanning [Start, End). The fields match
// the OpenTelemetry span shape — trace_id, span_id, parent_span_id,
// name, attributes — so a future migration to the full OTel SDK is a
// drop-in replacement: an OTLP exporter consumes these same fields.
//
// Until then, StdoutExporter serialises spans as one JSON object per
// line to any io.Writer (default: stderr). Production deployments
// either keep this for low-volume tracing or swap in the OTel SDK
// once go.mod adds the exporter packages.
type Span struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	ParentSpan string            `json:"parent_span_id,omitempty"`
	Name       string            `json:"name"`
	Start      time.Time         `json:"start"`
	End        time.Time         `json:"end"`
	DurationMs int64             `json:"duration_ms"`
	Attributes map[string]string `json:"attrs,omitempty"`
	StatusCode string            `json:"status,omitempty"`
}

// Exporter sinks Spans. StdoutExporter is the in-process
// implementation that writes one JSON line per span to a configurable
// io.Writer. Concurrent-safe via an internal mutex; spans are flushed
// synchronously on End() so callers can rely on the line landing
// before they return.
type Exporter interface {
	Export(span Span) error
	Close() error
}

// StdoutExporter writes one JSON span per line. Used by the in-process
// span recorder before a full OTel SDK lands.
type StdoutExporter struct {
	mu  sync.Mutex
	out io.Writer
}

// NewStdoutExporter constructs a StdoutExporter. Pass nil to use
// os.Stderr; production runs typically point this at the same sink
// the audit logger uses so traces and audit records correlate by
// request_id.
func NewStdoutExporter(out io.Writer) *StdoutExporter {
	if out == nil {
		// caller is responsible for choosing the right destination;
		// returning nil writer would NPE on first Export.
		panic("tracing: NewStdoutExporter requires a non-nil writer")
	}
	return &StdoutExporter{out: out}
}

// Export writes span as a single line of JSON.
func (e *StdoutExporter) Export(span Span) error {
	b, err := json.Marshal(span)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.out.Write(b); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "tracing: stdout exporter write", err)
	}
	return nil
}

// Close is a no-op for the stdout exporter — buffered writers (e.g.,
// bufio.Writer) layered on top of out should flush themselves.
func (e *StdoutExporter) Close() error { return nil }

// Recorder threads spans through ctx and exports them on End().
// Use Recorder.Start to open a span; the returned EndFunc closes it
// and ships it to the configured Exporter.
type Recorder struct {
	exporter Exporter
	now      func() time.Time
}

// NewRecorder constructs a Recorder. nil exporter is treated as a
// disabled tracer — Start returns a no-op EndFunc.
func NewRecorder(exporter Exporter) *Recorder {
	return &Recorder{exporter: exporter, now: time.Now}
}

// EndFunc is the callback Recorder.Start returns. Calling it twice
// is a no-op; calling it never simply means the span isn't exported.
type EndFunc func(attrs ...Attr)

// Attr is one structured attribute attached to a span at End() time.
type Attr struct {
	Key, Value string
}

// Start opens a new span named name and returns the EndFunc that
// closes it. The returned context carries the new span's TraceContext
// so nested Start calls get the right ParentSpan linkage.
func (r *Recorder) Start(ctx context.Context, name string) (context.Context, EndFunc) {
	if r == nil || r.exporter == nil {
		return ctx, func(_ ...Attr) {}
	}
	parent, _ := FromContext(ctx)
	var span TraceContext
	if parent.TraceID != [16]byte{} {
		child, err := parent.NewChildSpan()
		if err != nil {
			return ctx, func(_ ...Attr) {}
		}
		span = child
	} else {
		fresh, err := New()
		if err != nil {
			return ctx, func(_ ...Attr) {}
		}
		span = fresh
	}
	start := r.now()
	ended := false

	ctx = WithContext(ctx, span)
	return ctx, func(attrs ...Attr) {
		if ended {
			return
		}
		ended = true
		end := r.now()
		s := Span{
			TraceID:    span.TraceIDHex(),
			SpanID:     span.SpanIDHex(),
			Name:       name,
			Start:      start,
			End:        end,
			DurationMs: end.Sub(start).Milliseconds(),
		}
		if parent.TraceID != [16]byte{} {
			s.ParentSpan = parent.SpanIDHex()
		}
		if len(attrs) > 0 {
			s.Attributes = make(map[string]string, len(attrs))
			for _, a := range attrs {
				s.Attributes[a.Key] = a.Value
			}
		}
		_ = r.exporter.Export(s)
	}
}
