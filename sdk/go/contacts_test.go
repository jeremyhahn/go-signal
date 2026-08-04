package signal

import (
	"context"
	"testing"
)

func TestClient_ListContacts_Empty(t *testing.T) {
	c := newTestClient(t, "http://localhost", &mockStore{})
	contacts, err := c.ListContacts(context.Background())
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if len(contacts) != 0 {
		t.Errorf("expected 0 contacts, got %d", len(contacts))
	}
}

func TestClient_ListContacts_WithContacts(t *testing.T) {
	ms := &mockStore{
		contacts: []Contact{
			{Number: "+15550000001", Name: "Alice"},
			{Number: "+15550000002", Name: "Bob"},
		},
	}
	c := newTestClient(t, "http://localhost", ms)
	contacts, err := c.ListContacts(context.Background())
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if len(contacts) != 2 {
		t.Fatalf("expected 2 contacts, got %d", len(contacts))
	}
}

func TestClient_UpdateContact_NewContact(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	contact := Contact{Number: "+15550000001", Name: "Alice"}
	if err := c.UpdateContact(context.Background(), contact); err != nil {
		t.Fatalf("UpdateContact: %v", err)
	}
	if len(ms.contacts) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(ms.contacts))
	}
	if ms.contacts[0].Name != "Alice" {
		t.Errorf("Name = %q", ms.contacts[0].Name)
	}
}

func TestClient_UpdateContact_ExistingContact(t *testing.T) {
	ms := &mockStore{
		contacts: []Contact{{Number: "+15550000001", Name: "Old Name"}},
	}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.UpdateContact(context.Background(), Contact{Number: "+15550000001", Name: "New Name"}); err != nil {
		t.Fatalf("UpdateContact: %v", err)
	}
	if ms.contacts[0].Name != "New Name" {
		t.Errorf("Name = %q", ms.contacts[0].Name)
	}
}

func TestClient_RemoveContact_Success(t *testing.T) {
	ms := &mockStore{
		contacts: []Contact{
			{Number: "+15550000001", Name: "Alice"},
			{Number: "+15550000002", Name: "Bob"},
		},
	}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.RemoveContact(context.Background(), "+15550000001"); err != nil {
		t.Fatalf("RemoveContact: %v", err)
	}
	if len(ms.contacts) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(ms.contacts))
	}
	if ms.contacts[0].Number != "+15550000002" {
		t.Errorf("remaining contact = %q", ms.contacts[0].Number)
	}
}

func TestClient_RemoveContact_NotFound(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	// Removing a non-existent contact should not error.
	if err := c.RemoveContact(context.Background(), "+15559999999"); err != nil {
		t.Fatalf("RemoveContact: %v", err)
	}
}

func TestClient_Block_ExistingContact(t *testing.T) {
	ms := &mockStore{
		contacts: []Contact{{Number: "+15550000001", Name: "Alice", Blocked: false}},
	}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.Block(context.Background(), "+15550000001"); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !ms.contacts[0].Blocked {
		t.Error("expected contact to be blocked")
	}
}

func TestClient_Block_NewContact(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.Block(context.Background(), "+15550000099"); err != nil {
		t.Fatalf("Block (new): %v", err)
	}
	found := false
	for _, ct := range ms.contacts {
		if ct.Number == "+15550000099" && ct.Blocked {
			found = true
		}
	}
	if !found {
		t.Error("expected new blocked contact to be created")
	}
}

func TestClient_Block_ByUUID(t *testing.T) {
	ms := &mockStore{
		contacts: []Contact{{Number: "+15550000001", UUID: "user-uuid-1", Blocked: false}},
	}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.Block(context.Background(), "user-uuid-1"); err != nil {
		t.Fatalf("Block by UUID: %v", err)
	}
	if !ms.contacts[0].Blocked {
		t.Error("expected contact to be blocked via UUID lookup")
	}
}

func TestClient_Unblock_ExistingContact(t *testing.T) {
	ms := &mockStore{
		contacts: []Contact{{Number: "+15550000001", Name: "Alice", Blocked: true}},
	}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.Unblock(context.Background(), "+15550000001"); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if ms.contacts[0].Blocked {
		t.Error("expected contact to be unblocked")
	}
}

func TestClient_Unblock_NotFound(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	// Unblocking a non-existent contact should not error.
	if err := c.Unblock(context.Background(), "+15559999999"); err != nil {
		t.Fatalf("Unblock non-existent: %v", err)
	}
}
