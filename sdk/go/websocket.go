package signal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// WSClient manages a persistent WebSocket connection to the Signal server
// for real-time message delivery.
type WSClient struct {
	mu       sync.Mutex
	conn     *websocket.Conn
	url      string
	username string
	password string
	caCert   string
	closed   bool
	onMessage func([]byte)
}

// ConnectWebSocket establishes a persistent WebSocket connection for
// real-time message delivery. Messages received are passed to the handler.
func (c *Client) ConnectWebSocket(ctx context.Context, handler func(msg ReceivedMessage)) error {
	creds, err := c.store.GetCredentials()
	if err != nil || creds == nil {
		return fmt.Errorf("no credentials for WebSocket connection")
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

	conn, _, err := websocket.Dial(ctx, wsURL, opts)
	if err != nil {
		return fmt.Errorf("WebSocket connect: %w", err)
	}

	// Read messages in a loop.
	go func() {
		defer conn.CloseNow()
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

	return nil
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
