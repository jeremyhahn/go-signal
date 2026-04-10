package accounts

import "context"

// AccountStore defines the storage interface for Signal accounts.
type AccountStore interface {
	// Create persists a new account.
	Create(ctx context.Context, account *Account) error

	// Get retrieves an account by UUID.
	Get(ctx context.Context, uuid string) (*Account, error)

	// GetByNumber retrieves an account by phone number.
	GetByNumber(ctx context.Context, number string) (*Account, error)

	// Update persists changes to an existing account.
	Update(ctx context.Context, account *Account) error

	// Delete removes an account by UUID.
	Delete(ctx context.Context, uuid string) error
}
