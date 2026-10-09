//go:build desktop

package desktop

import (
	"context"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
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
// App wraps the client with Wails-bound methods for the React frontend. ctx
// bounds loading the saved credentials into protected memory.
func NewApp(ctx context.Context, cfg signal.ClientConfig) (*App, error) {
	client, err := signal.NewClient(ctx, cfg)
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
		// Wails binds the frontend methods before it calls Startup, so the
		// application context has to be usable from construction. Startup
		// replaces it with the runtime context.
		ctx:    ctx,
		client: client,
		daos:   factory,
	}, nil
}

// Startup is called by Wails when the application starts.
// The context is saved for runtime event emission and supersedes the one
// NewApp was given.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
}

// Shutdown is called by Wails when the application is closing. It is the void
// adapter Wails' lifecycle requires and discards the close error because Wails
// has nowhere to put one; callers that can report a failure should use Close.
func (a *App) Shutdown(_ context.Context) {
	_ = a.Close()
}

// Close releases the client and the store it owns, reporting any failure.
//
// A store that will not close is a persistence failure — an unflushed write is
// lost data, not a tidy-up detail — so the error is returned rather than
// dropped.
func (a *App) Close() error {
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

// ---------------------------------------------------------------------------
// Account bindings (exposed to frontend)
// ---------------------------------------------------------------------------

// IsRegistered checks whether the client has stored credentials, under the
// application context Wails hands to Startup.
func (a *App) IsRegistered() (bool, error) {
	creds, err := a.client.Config().Store.GetCredentials(a.ctx)
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
