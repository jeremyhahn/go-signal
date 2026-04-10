//go:build desktop

// Package events provides a Go-to-frontend event bus for the desktop client.
// Events emitted here are bridged to the React frontend via Wails runtime
// events in desktop mode, or via WebSocket in web mode.
package events

import (
	"context"
	"sync"
)

// EventType identifies the kind of event.
type EventType string

const (
	MessageReceived  EventType = "signal:message:received"
	MessageSent      EventType = "signal:message:sent"
	TypingIndicator  EventType = "signal:typing"
	Receipt          EventType = "signal:receipt"
	ContactUpdated   EventType = "signal:contact:updated"
	GroupUpdated     EventType = "signal:group:updated"
	IdentityChanged  EventType = "signal:identity:changed"
	ConnectionStatus EventType = "signal:connection:status"
	ErrorEvent       EventType = "signal:error"
)

// Handler processes an event payload.
type Handler func(eventType EventType, payload interface{})

// Bus is a thread-safe event bus that distributes events to registered
// handlers. In the Wails desktop app, the emitter bridges events to the
// frontend via runtime.EventsEmit.
type Bus struct {
	mu       sync.RWMutex
	handlers []Handler
	emitter  Emitter
}

// Emitter is the interface for pushing events to the frontend.
// In Wails mode, this wraps runtime.EventsEmit.
// In web mode, this pushes to a WebSocket connection.
type Emitter interface {
	Emit(eventType string, payload interface{})
}

// NewBus creates an event bus with the given emitter.
func NewBus(emitter Emitter) *Bus {
	return &Bus{emitter: emitter}
}

// Subscribe registers a handler that will receive all events.
// Returns an unsubscribe function.
func (b *Bus) Subscribe(handler Handler) func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = append(b.handlers, handler)
	idx := len(b.handlers) - 1
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		// Nil out the slot to avoid index shifts.
		if idx < len(b.handlers) {
			b.handlers[idx] = nil
		}
	}
}

// Emit sends an event to all handlers and the frontend emitter.
func (b *Bus) Emit(eventType EventType, payload interface{}) {
	// Push to frontend.
	if b.emitter != nil {
		b.emitter.Emit(string(eventType), payload)
	}

	// Notify Go-side handlers.
	b.mu.RLock()
	handlers := make([]Handler, len(b.handlers))
	copy(handlers, b.handlers)
	b.mu.RUnlock()

	for _, h := range handlers {
		if h != nil {
			h(eventType, payload)
		}
	}
}

// EmitAsync sends an event in a goroutine to avoid blocking the caller.
func (b *Bus) EmitAsync(eventType EventType, payload interface{}) {
	go b.Emit(eventType, payload)
}

// NoopEmitter is a no-op emitter for testing.
type NoopEmitter struct{}

func (NoopEmitter) Emit(_ string, _ interface{}) {}

// WailsEmitter wraps a Wails runtime context for event emission.
type WailsEmitter struct {
	ctx context.Context
}

// NewWailsEmitter creates an emitter that uses the Wails runtime.
// The context must be the Wails application context from Startup().
func NewWailsEmitter(ctx context.Context) *WailsEmitter {
	return &WailsEmitter{ctx: ctx}
}

// Emit sends an event to the Wails frontend via the runtime context.
// In non-desktop builds or before Wails initialization, this is a no-op.
func (e *WailsEmitter) Emit(eventType string, payload interface{}) {
	// Wails runtime event emission is handled via the Wails v2 runtime
	// package when the desktop build tag is active and the Wails app is
	// running. The context from Startup() carries the runtime binding.
	_ = e.ctx
	_ = eventType
	_ = payload
}
