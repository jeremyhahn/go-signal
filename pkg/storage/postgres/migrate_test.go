package postgres

import (
	"context"
	"testing"
)

func TestMigrate_Idempotent(t *testing.T) {
	c := newTestClient(t)
	// newTestClient already migrated; running again must be a no-op.
	if err := c.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate (second run): %v", err)
	}
}

func TestMigrate_RecordedInSchemaTable(t *testing.T) {
	c := newTestClient(t)
	var count int
	if err := c.Pool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if count == 0 {
		t.Fatal("schema_migrations should have at least one row")
	}
}

// TestMigrate_AlreadyUpToDate exercises the branch where all migration
// versions are already applied and Migrate returns without doing any work.
func TestMigrate_AlreadyUpToDate_NoOp(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	// newTestClient already migrated once. A second and third call must be no-ops.
	for i := range 2 {
		if err := c.Migrate(ctx); err != nil {
			t.Fatalf("Migrate run %d: %v", i+2, err)
		}
	}

	// The count of schema_migrations rows must remain stable across repeated runs.
	var count1, count2 int
	if err := c.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count1); err != nil {
		t.Fatalf("COUNT after 2nd run: %v", err)
	}
	if err := c.Migrate(ctx); err != nil {
		t.Fatalf("Migrate run 3: %v", err)
	}
	if err := c.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count2); err != nil {
		t.Fatalf("COUNT after 3rd run: %v", err)
	}
	if count1 != count2 {
		t.Fatalf("row count changed across idempotent runs: %d -> %d", count1, count2)
	}
}

func TestLoadMigrations_ParsesEmbedded(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	for _, m := range migs {
		if m.up == "" {
			t.Errorf("migration %d has empty up", m.version)
		}
		if m.version <= 0 {
			t.Errorf("migration %d has invalid version", m.version)
		}
	}
}
