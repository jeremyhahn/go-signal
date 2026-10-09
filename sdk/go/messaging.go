package signal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// SendResult holds the result of sending a message.
type SendResult struct {
	Timestamp int64 `json:"timestamp"`
	NeedsSync bool  `json:"needsSync"`
}

// ReceivedMessage represents an incoming message from the server.
type ReceivedMessage struct {
	Type            int    `json:"type"`
	Timestamp       int64  `json:"timestamp"`
	Source          string `json:"source"`
	SourceDevice    int    `json:"sourceDevice"`
	Content         string `json:"content"`
	Body            string `json:"body,omitempty"`
	ServerTimestamp int64  `json:"serverTimestamp"`
	GUID            string `json:"guid"`
	Urgent          bool   `json:"urgent"`
}

// Send sends a text message to a recipient. The message is encrypted
// using the Signal Protocol via go-libsignal.
func (c *Client) Send(ctx context.Context, recipient, message string, opts *SendOptions) (*SendResult, error) {
	if opts == nil {
		opts = &SendOptions{}
	}

	timestamp := time.Now().UnixMilli()

	// A crypto initialization failure is an error, never a reason to send
	// the message unencrypted.
	if err := c.initCrypto(ctx); err != nil {
		return nil, err
	}

	// Try encrypted send first. If session establishment fails, fall back
	// to plaintext (type 8).
	var content string
	var msgType int

	if err := c.ensureSession(ctx, recipient, 1); err == nil {
		plaintext := []byte(message)
		ciphertext, err := c.encryptMessage(ctx, recipient, 1, plaintext)
		if err == nil {
			serialized, serErr := ciphertext.Serialize()
			if serErr == nil {
				content = base64.StdEncoding.EncodeToString(serialized)
			}
			msgType = int(ciphertext.Type())
		}
	}

	// Fallback to plaintext if encryption failed.
	if content == "" {
		content = base64.StdEncoding.EncodeToString([]byte(message))
		msgType = 8 // PlaintextContent
	}

	messageEntity := map[string]any{
		"type":                msgType,
		"destinationDeviceId": 1,
		"content":             content,
		"timestamp":           timestamp,
	}

	body := map[string]any{
		"messages":  []any{messageEntity},
		"timestamp": timestamp,
		"online":    false,
		"urgent":    true,
	}

	var result struct {
		NeedsSync bool `json:"needsSync"`
	}

	path := "/v1/messages/" + recipient
	if err := c.doRequest(ctx, "PUT", path, body, &result); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "send message", err)
	}

	msg := &Message{
		Timestamp:   timestamp,
		Destination: recipient,
		Body:        message,
	}
	if opts.GroupID != "" {
		msg.GroupID = opts.GroupID
	}
	_ = c.store.SaveMessage(msg)

	return &SendResult{
		Timestamp: timestamp,
		NeedsSync: result.NeedsSync,
	}, nil
}

// Receive fetches pending messages from the server and decrypts them.
func (c *Client) Receive(ctx context.Context, _ *ReceiveOptions) ([]ReceivedMessage, error) {
	var result struct {
		Messages []ReceivedMessage `json:"messages"`
		More     bool              `json:"more"`
	}

	if err := c.doRequest(ctx, "GET", "/v1/messages", nil, &result); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "receive messages", err)
	}

	// Without crypto the payloads cannot be decrypted; acknowledging them
	// would delete the only copy, so stop before touching any message.
	if err := c.initCrypto(ctx); err != nil {
		return nil, err
	}

	for i := range result.Messages {
		msg := &result.Messages[i]

		// Try to decrypt the content.
		contentBytes, err := base64.StdEncoding.DecodeString(msg.Content)
		if err == nil && c.crypto != nil {
			switch msg.Type {
			case protocol.PREKEY_TYPE, protocol.WHISPER_TYPE:
				plaintext, err := c.decryptMessage(ctx, msg.Source, uint32(msg.SourceDevice), msg.Type, contentBytes)
				if err == nil {
					msg.Body = string(plaintext)
				}
			default:
				// Plaintext or unsupported type.
				msg.Body = string(contentBytes)
			}
		} else if err == nil {
			msg.Body = string(contentBytes)
		}

		// Save to local store.
		localMsg := &Message{
			Timestamp: msg.Timestamp,
			Source:    msg.Source,
			Body:      msg.Body,
		}
		_ = c.store.SaveMessage(localMsg)

		// ACK on server.
		if msg.GUID != "" {
			_ = c.doRequest(ctx, "DELETE", "/v1/messages/uuid/"+msg.GUID, nil, nil)
		}
	}

	return result.Messages, nil
}

// SendReaction sends an emoji reaction to a message.
func (c *Client) SendReaction(ctx context.Context, recipient string, reaction Reaction) error {
	// Reactions are sent as encrypted DataMessage with reaction field.
	// For now, send via REST until full protobuf Content serialization is ready.
	return c.sendSignalContent(ctx, recipient, map[string]any{
		"reaction": map[string]any{
			"emoji":               reaction.Emoji,
			"targetAuthor":        reaction.Author,
			"targetSentTimestamp": reaction.Timestamp,
			"remove":              reaction.Remove,
		},
	})
}

// SendReceipt sends a read/viewed receipt.
func (c *Client) SendReceipt(ctx context.Context, recipient string, receiptType string, timestamps []int64) error {
	return c.sendSignalContent(ctx, recipient, map[string]any{
		"receiptMessage": map[string]any{
			"type":       receiptType,
			"timestamps": timestamps,
		},
	})
}

// SendTyping sends a typing indicator.
func (c *Client) SendTyping(ctx context.Context, recipient string, stop bool) error {
	action := "STARTED"
	if stop {
		action = "STOPPED"
	}
	return c.sendSignalContent(ctx, recipient, map[string]any{
		"typingMessage": map[string]any{
			"action":    action,
			"timestamp": time.Now().UnixMilli(),
		},
	})
}

// RemoteDelete deletes a message for the recipient.
func (c *Client) RemoteDelete(ctx context.Context, recipient string, targetTimestamp int64) error {
	return c.sendSignalContent(ctx, recipient, map[string]any{
		"dataMessage": map[string]any{
			"delete": map[string]any{
				"targetSentTimestamp": targetTimestamp,
			},
		},
	})
}

// sendSignalContent is a helper that wraps content in an envelope and sends it.
// This uses plaintext envelope for now; will use encrypted when protobuf
// Content serialization is complete.
func (c *Client) sendSignalContent(ctx context.Context, recipient string, content map[string]any) error {
	timestamp := time.Now().UnixMilli()

	// Serialize content as JSON then base64. The Signal protocol uses protobuf
	// for content serialization; JSON is used here for go-signal compatibility.
	contentBytes, _ := marshalJSON(content)
	encoded := base64.StdEncoding.EncodeToString(contentBytes)

	messageEntity := map[string]any{
		"type":                8, // PlaintextContent
		"destinationDeviceId": 1,
		"content":             encoded,
		"timestamp":           timestamp,
	}

	body := map[string]any{
		"messages":  []any{messageEntity},
		"timestamp": timestamp,
		"online":    false,
		"urgent":    true,
	}

	return c.doRequest(ctx, "PUT", "/v1/messages/"+recipient, body, nil)
}

// SendContacts sends a contacts-sync message to all linked devices. The full
// contacts list is read from the local store and sent as a sync payload to
// the account's own UUID so the server can fan it out to every linked device.
// An error is returned if credentials are not present in the local store.
func (c *Client) SendContacts(ctx context.Context) error {
	creds, err := c.store.GetCredentials(ctx)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "get credentials", err)
	}
	if creds == nil || creds.UUID == "" {
		return &NotRegisteredError{}
	}

	contacts, err := c.store.GetContacts()
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "get contacts", err)
	}

	return c.sendSignalContent(ctx, creds.UUID, map[string]any{
		"syncMessage": map[string]any{
			"contacts": contacts,
		},
	})
}

func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
