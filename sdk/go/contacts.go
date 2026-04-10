package signal

import "context"

// ListContacts returns all stored contacts.
func (c *Client) ListContacts(ctx context.Context) ([]Contact, error) {
	return c.store.GetContacts()
}

// UpdateContact adds or updates a contact.
func (c *Client) UpdateContact(ctx context.Context, contact Contact) error {
	return c.store.SaveContact(&contact)
}

// RemoveContact removes a contact.
func (c *Client) RemoveContact(ctx context.Context, number string) error {
	return c.store.DeleteContact(number)
}

// Block blocks a contact or group.
func (c *Client) Block(ctx context.Context, identifier string) error {
	contacts, _ := c.store.GetContacts()
	for i, ct := range contacts {
		if ct.Number == identifier || ct.UUID == identifier {
			contacts[i].Blocked = true
			return c.store.SaveContact(&contacts[i])
		}
	}
	// Create new blocked contact.
	return c.store.SaveContact(&Contact{Number: identifier, Blocked: true})
}

// Unblock unblocks a contact or group.
func (c *Client) Unblock(ctx context.Context, identifier string) error {
	contacts, _ := c.store.GetContacts()
	for i, ct := range contacts {
		if ct.Number == identifier || ct.UUID == identifier {
			contacts[i].Blocked = false
			return c.store.SaveContact(&contacts[i])
		}
	}
	return nil
}
