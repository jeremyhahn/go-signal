package accounts

import "context"

// AccountStore defines the storage interface for Signal accounts.
type AccountStore interface {
	// Create persists a new account.
	Create(ctx context.Context, account *Account) error

	// Get retrieves an account by UUID (ACI).
	Get(ctx context.Context, uuid string) (*Account, error)

	// GetByNumber retrieves an account by phone number.
	GetByNumber(ctx context.Context, number string) (*Account, error)

	// GetByPNI retrieves an account by its Phone Number Identity UUID.
	// Returns *AccountNotFoundError when no account maps to pni.
	GetByPNI(ctx context.Context, pni string) (*Account, error)

	// Update persists changes to an existing account.
	Update(ctx context.Context, account *Account) error

	// Delete removes an account by UUID.
	Delete(ctx context.Context, uuid string) error

	// ListAll streams every account to fn; an error from fn aborts. Order is not guaranteed.
	ListAll(ctx context.Context, fn func(*Account) error) error
}
