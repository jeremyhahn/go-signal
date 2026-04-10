//go:build desktop

package desktop

import (
	"context"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// App is the Wails-bound application struct. Its exported methods are
// available to the React frontend via auto-generated TypeScript bindings.
type App struct {
	ctx    context.Context
	client *signal.Client
	daos   *daostore.Factory
}

// NewApp creates the desktop application. The Signal SDK client is created
// with a QRDB-backed DAOStore by default (shared with the CLI). The desktop
// App wraps the client with Wails-bound methods for the React frontend.
func NewApp(cfg signal.ClientConfig) (*App, error) {
	client, err := signal.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// Extract the DAO factory from the client's store for direct DAO access
	// in bindings (conversations, messages, etc.).
	var factory *daostore.Factory
	if daoStore, ok := client.Config().Store.(*signal.DAOStore); ok {
		factory = daoStore.Factory()
	}

	return &App{
		client: client,
		daos:   factory,
	}, nil
}

// Startup is called by Wails when the application starts.
// The context is saved for runtime event emission.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
}

// Shutdown is called by Wails when the application is closing.
func (a *App) Shutdown(_ context.Context) {
	if a.client != nil {
		_ = a.client.Close()
	}
}

// ---------------------------------------------------------------------------
// Account bindings (exposed to frontend)
// ---------------------------------------------------------------------------

// IsRegistered checks whether the client has stored credentials.
func (a *App) IsRegistered() (bool, error) {
	creds, err := a.client.Config().Store.GetCredentials()
	if err != nil {
		return false, nil
	}
	return creds != nil && creds.UUID != "", nil
}

// WhoAmI returns the current account info.
func (a *App) WhoAmI() (*signal.Account, error) {
	return a.client.WhoAmI(context.Background())
}

// Register completes account registration.
func (a *App) Register(number, sessionID string) (*signal.RegistrationResult, error) {
	return a.client.Register(context.Background(), number, sessionID)
}

// CreateVerificationSession starts phone number verification.
func (a *App) CreateVerificationSession(number string) (*signal.VerificationSession, error) {
	return a.client.CreateVerificationSession(context.Background(), number)
}

// RequestVerificationCode sends the verification code via SMS/voice.
func (a *App) RequestVerificationCode(sessionID string) (*signal.VerificationSession, error) {
	return a.client.RequestVerificationCode(context.Background(), sessionID)
}

// SubmitVerificationCode submits the verification code.
func (a *App) SubmitVerificationCode(sessionID, code string) (*signal.VerificationSession, error) {
	return a.client.SubmitVerificationCode(context.Background(), sessionID, code)
}

// ---------------------------------------------------------------------------
// Messaging bindings
// ---------------------------------------------------------------------------

// SendMessage sends a text message to a recipient.
func (a *App) SendMessage(recipient, body string) (*signal.SendResult, error) {
	return a.client.Send(context.Background(), recipient, body, nil)
}

// GetConversations returns all conversations sorted by last activity.
func (a *App) GetConversations() ([]*entities.ConversationEntity, error) {
	ctx := context.Background()
	return a.daos.Conversations.Find(ctx).
		OrderBy("ActiveAt", dao.SortDescending).
		Execute()
}

