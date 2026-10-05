package signal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/coder/websocket"
)

// ConnectWebSocket establishes a persistent WebSocket connection for
// real-time message delivery. Messages received are passed to the handler.
// ConnectWebSocketSession dials the authenticated WebSocket and reads messages
// on a background goroutine. It returns as soon as the handshake completes,
// NOT when the connection ends.
//
// The returned channel is closed when the session's read loop exits — server
// close, network drop, or ctx cancellation. Callers that maintain a
// persistent connection must wait on it: without it there is no way to notice
// a dropped socket, so a reconnecting client silently stops receiving.
func (c *Client) ConnectWebSocketSession(ctx context.Context, handler func(msg ReceivedMessage)) (<-chan struct{}, error) {
	creds, err := c.store.GetCredentials()
	if err != nil || creds == nil {
		return nil, signalerrors.New(signalerrors.ErrUnauthenticated, "no credentials for WebSocket connection")
	}

	scheme := "wss"
	serverURL := c.config.ServerURL
	// Replace https:// with wss://
	if len(serverURL) > 8 && serverURL[:8] == "https://" {
		serverURL = scheme + "://" + serverURL[8:]
	} else if len(serverURL) > 7 && serverURL[:7] == "http://" {
		serverURL = "ws://" + serverURL[7:]
	}

	wsURL := serverURL + "/v1/websocket/"

	// Build TLS config with custom CA if needed.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.config.CACert != nil && !c.config.CACert.IsDestroyed() {
		caBytes := c.config.CACert.Bytes()
		if caBytes != nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caBytes)
			tlsConfig.RootCAs = pool
			for i := range caBytes {
				caBytes[i] = 0
			}
		}
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	// Connect with Basic Auth via header. Extract password securely.
	username := fmt.Sprintf("%s.%d", creds.UUID, creds.DeviceID)
	pw := ""
	if creds.Password != nil {
		pw = creds.Password.Plaintext()
	}
	opts := &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: http.Header{
			"Authorization": []string{basicAuth(username, pw)},
		},
	}

	conn, _, err := websocket.Dial(ctx, wsURL, opts) //nolint:bodyclose // coder/websocket owns the handshake response; its Dial docs state you never close resp.Body yourself.
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "WebSocket connect", err)
	}

	// Read messages in a loop. done is closed as this goroutine returns, which
	// is the only way a caller can learn the session ended: the read loop
	// exits on a server close, a network drop, or context cancellation, and
	// none of those are otherwise observable from outside.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = conn.CloseNow() }()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			// Decode the raw WebSocket frame into a ReceivedMessage.
			// The server sends JSON-encoded message envelopes.
			var msg ReceivedMessage
			if jsonErr := json.Unmarshal(data, &msg); jsonErr != nil {
				continue // skip malformed frames
			}
			handler(msg)
		}
	}()

	return done, nil
}

// ConnectWebSocket dials the authenticated WebSocket and reads messages on a
// background goroutine, discarding the session-termination signal.
//
// Prefer ConnectWebSocketSession for anything that must react to the
// connection ending — a caller that only has this signature cannot tell a
// live connection from one the server closed a moment later.
func (c *Client) ConnectWebSocket(ctx context.Context, handler func(msg ReceivedMessage)) error {
	_, err := c.ConnectWebSocketSession(ctx, handler)
	return err
}

// ReceiveWebSocket connects via WebSocket and waits for messages
// for the specified duration.
func (c *Client) ReceiveWebSocket(ctx context.Context, timeout time.Duration) ([]ReceivedMessage, error) {
	// For now, fall back to REST polling.
	// Full WebSocket implementation will parse protobuf frames.
	return c.Receive(ctx, &ReceiveOptions{Timeout: int(timeout.Seconds())})
}

func basicAuth(username, password string) string {
	cred := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))
}
