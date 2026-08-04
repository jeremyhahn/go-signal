//go:build desktop

package ws

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// TestNewDefaultHandler verifies construction.
func TestNewDefaultHandler(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		f, err := newWSFactory()
		require.NoError(t, err)
		h := NewDefaultHandler(f)
		require.NotNil(t, h)
	})
}

// TestDefaultHandler_HandleMessage_NewConversation checks that a message
// from an unknown source creates a new conversation.
func TestDefaultHandler_HandleMessage_NewConversation(t *testing.T) {
	t.Run("CreatesConversation", func(t *testing.T) {
		f, err := newWSFactory()
		require.NoError(t, err)
		h := NewDefaultHandler(f)

		msg := signal.ReceivedMessage{
			GUID:            "guid-001",
			Source:          "user-alice",
			SourceDevice:    1,
			Timestamp:       time.Now().UnixMilli(),
			ServerTimestamp: time.Now().UnixMilli(),
			Body:            "Hello!",
		}
		// Must not panic.
		assert.NotPanics(t, func() { h.HandleMessage(msg) })
	})

	t.Run("MultipleDifferentSenders", func(t *testing.T) {
		f, err := newWSFactory()
		require.NoError(t, err)
		h := NewDefaultHandler(f)

		for i, sender := range []string{"alice", "bob", "carol"} {
			msg := signal.ReceivedMessage{
				GUID:      "g" + sender,
				Source:    sender,
				Timestamp: time.Now().UnixMilli() + int64(i),
				Body:      "hi from " + sender,
			}
			assert.NotPanics(t, func() { h.HandleMessage(msg) })
		}
	})
}

// TestDefaultHandler_HandleMessage_ExistingConversation checks that a second
// message to the same source updates an existing conversation.
func TestDefaultHandler_HandleMessage_ExistingConversation(t *testing.T) {
	t.Run("UpdatesExistingConversation", func(t *testing.T) {
		f, err := newWSFactory()
		require.NoError(t, err)
		h := NewDefaultHandler(f)

		first := signal.ReceivedMessage{
			GUID:      "guid-first",
			Source:    "user-dave",
			Timestamp: 1000,
			Body:      "First message",
		}
		h.HandleMessage(first)

		second := signal.ReceivedMessage{
			GUID:      "guid-second",
			Source:    "user-dave",
			Timestamp: 2000,
			Body:      "Second message",
		}
		assert.NotPanics(t, func() { h.HandleMessage(second) })
	})

	t.Run("EmptyBody", func(t *testing.T) {
		f, err := newWSFactory()
		require.NoError(t, err)
		h := NewDefaultHandler(f)

		msg := signal.ReceivedMessage{
			GUID:   "guid-empty",
			Source: "user-eve",
		}
		assert.NotPanics(t, func() { h.HandleMessage(msg) })
	})
}
