//go:build desktop

package events

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureEmitter records the most recent Emit call for assertions.
type captureEmitter struct {
	mu       sync.Mutex
	events   []string
	payloads []interface{}
}

func (e *captureEmitter) Emit(eventType string, payload interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, eventType)
	e.payloads = append(e.payloads, payload)
}

func (e *captureEmitter) last() (string, interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.events) == 0 {
		return "", nil
	}
	n := len(e.events)
	return e.events[n-1], e.payloads[n-1]
}

func (e *captureEmitter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

// TestNewBus verifies that NewBus constructs a non-nil bus.
func TestNewBus(t *testing.T) {
	t.Run("WithEmitter", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		require.NotNil(t, b)
	})
	t.Run("NilEmitter", func(t *testing.T) {
		b := NewBus(nil)
		require.NotNil(t, b)
	})
}

// TestBus_Subscribe checks that registered handlers receive events.
func TestBus_Subscribe(t *testing.T) {
	t.Run("HandlerReceivesEvent", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		var got EventType
		b.Subscribe(func(et EventType, _ interface{}) {
			got = et
		})
		b.Emit(MessageReceived, "hello")
		assert.Equal(t, MessageReceived, got)
	})

	t.Run("MultipleHandlers", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		var calls int
		b.Subscribe(func(_ EventType, _ interface{}) { calls++ })
		b.Subscribe(func(_ EventType, _ interface{}) { calls++ })
		b.Emit(MessageSent, nil)
		assert.Equal(t, 2, calls)
	})
}

// TestBus_Unsubscribe verifies that the returned function removes the handler.
func TestBus_Unsubscribe(t *testing.T) {
	t.Run("UnsubscribeStopsDelivery", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		var calls int
		unsub := b.Subscribe(func(_ EventType, _ interface{}) { calls++ })
		b.Emit(Receipt, nil)
		assert.Equal(t, 1, calls)

		unsub()
		b.Emit(Receipt, nil)
		// handler slot is nil'd; call count stays at 1.
		assert.Equal(t, 1, calls)
	})

	t.Run("UnsubscribeOutOfBoundsIsSafe", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		unsub := b.Subscribe(func(_ EventType, _ interface{}) {})
		unsub()
		// calling again must not panic.
		assert.NotPanics(t, unsub)
	})
}

// TestBus_Emit checks that the emitter and handlers both receive the event.
func TestBus_Emit(t *testing.T) {
	t.Run("EmitterReceivesEvent", func(t *testing.T) {
		ce := &captureEmitter{}
		b := NewBus(ce)
		b.Emit(TypingIndicator, map[string]bool{"started": true})
		et, _ := ce.last()
		assert.Equal(t, string(TypingIndicator), et)
	})

	t.Run("NilEmitterDoesNotPanic", func(t *testing.T) {
		b := NewBus(nil)
		assert.NotPanics(t, func() {
			b.Emit(ErrorEvent, "oops")
		})
	})

	t.Run("PayloadPassedThrough", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		payload := map[string]int{"count": 42}
		var got interface{}
		b.Subscribe(func(_ EventType, p interface{}) { got = p })
		b.Emit(ContactUpdated, payload)
		assert.Equal(t, payload, got)
	})

	t.Run("AllEventTypes", func(t *testing.T) {
		types := []EventType{
			MessageReceived, MessageSent, TypingIndicator, Receipt,
			ContactUpdated, GroupUpdated, IdentityChanged, ConnectionStatus, ErrorEvent,
		}
		ce := &captureEmitter{}
		b := NewBus(ce)
		for _, et := range types {
			b.Emit(et, nil)
		}
		assert.Equal(t, len(types), ce.count())
	})
}

// TestBus_EmitAsync verifies that events are delivered asynchronously.
func TestBus_EmitAsync(t *testing.T) {
	t.Run("HandlerCalledEventually", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		var wg sync.WaitGroup
		wg.Add(1)
		b.Subscribe(func(et EventType, _ interface{}) {
			if et == GroupUpdated {
				wg.Done()
			}
		})
		b.EmitAsync(GroupUpdated, nil)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("EmitAsync: handler not called within timeout")
		}
	})

	t.Run("DoesNotBlockCaller", func(t *testing.T) {
		b := NewBus(NoopEmitter{})
		// A slow handler should not block EmitAsync.
		b.Subscribe(func(_ EventType, _ interface{}) {
			time.Sleep(500 * time.Millisecond)
		})
		start := time.Now()
		b.EmitAsync(ConnectionStatus, nil)
		assert.Less(t, time.Since(start), 100*time.Millisecond)
	})
}

// TestNoopEmitter verifies that NoopEmitter.Emit is a no-op.
func TestNoopEmitter(t *testing.T) {
	t.Run("DoesNotPanic", func(t *testing.T) {
		var e Emitter = NoopEmitter{}
		assert.NotPanics(t, func() {
			e.Emit(string(MessageReceived), "payload")
		})
	})
	t.Run("ImplementsEmitter", func(t *testing.T) {
		// Compile-time check.
		var _ Emitter = NoopEmitter{}
	})
}

// TestNewWailsEmitter verifies the constructor does not panic.
func TestNewWailsEmitter(t *testing.T) {
	t.Run("NilContext", func(t *testing.T) {
		e := NewWailsEmitter(nil)
		require.NotNil(t, e)
	})
	t.Run("EmitIsNoOp", func(t *testing.T) {
		e := NewWailsEmitter(nil)
		// Must not panic; it is a no-op until the Wails runtime is active.
		assert.NotPanics(t, func() {
			e.Emit(string(MessageReceived), "test")
		})
	})
}

// TestBus_ConcurrentEmit checks that concurrent Emit calls are race-free.
func TestBus_ConcurrentEmit(t *testing.T) {
	b := NewBus(NoopEmitter{})
	var mu sync.Mutex
	count := 0
	b.Subscribe(func(_ EventType, _ interface{}) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			b.Emit(MessageReceived, nil)
		}()
	}
	wg.Wait()
	assert.Equal(t, goroutines, count)
}
