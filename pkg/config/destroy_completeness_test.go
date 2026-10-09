package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// secureStringType is the type the walk below looks for.
var secureStringType = reflect.TypeOf((*secrets.SecureString)(nil))

// walkProtectedFields visits every *secrets.SecureString reachable from v by
// exported fields, reporting each with a dotted path so a failure names the
// field rather than an offset. Only exported fields are visited, which matches
// what Config.Destroy can reach.
func walkProtectedFields(v reflect.Value, path string, visit func(path string, field reflect.Value)) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.Type() == secureStringType {
			visit(path, v)
			return
		}
		if !v.IsNil() {
			walkProtectedFields(v.Elem(), path, visit)
		}
	case reflect.Struct:
		t := v.Type()
		for i := range v.NumField() {
			if !t.Field(i).IsExported() {
				continue
			}
			name := t.Field(i).Name
			next := name
			if path != "" {
				next = path + "." + name
			}
			walkProtectedFields(v.Field(i), next, visit)
		}
	}
}

// TestDestroy_WipesEveryProtectedFieldInTheConfigTree is the drift guard for
// Config.Destroy.
//
// Destroy enumerates the protected fields by hand. That list has already
// drifted once — Storage.Postgres.URL holds a database DSN with embedded
// credentials and was missing from it, so a failed load or a normal shutdown
// left the URL resident while wiping everything around it. A hand-maintained
// list of twenty fields will drift again; the fields are added one at a time,
// in different PRs, by whoever needs them.
//
// So this does not test that one field. It walks the whole Config tree by
// reflection, populates EVERY *secrets.SecureString it finds, calls Destroy,
// and asserts every one of them is wiped. A field added to Config without
// being added to Destroy fails here automatically, naming itself.
//
// Removing any field from Destroy's list makes this fail.
func TestDestroy_WipesEveryProtectedFieldInTheConfigTree(t *testing.T) {
	cfg := &Config{}

	// Populate every protected field, so none of them is vacuously "already
	// destroyed" when Destroy runs.
	var populated []string
	walkProtectedFields(reflect.ValueOf(cfg), "", func(path string, field reflect.Value) {
		if !field.CanSet() {
			t.Fatalf("%s is not settable — the walk cannot populate it, so this test would pass vacuously", path)
		}
		field.Set(reflect.ValueOf(secrets.MustNewSecureString(t.Context(), "value-for-"+path)))
		populated = append(populated, path)
	})

	if len(populated) == 0 {
		t.Fatal("the walk found no protected fields — it is not reaching into Config")
	}
	t.Logf("populated %d protected fields", len(populated))

	cfg.Destroy()

	var survivors []string
	walkProtectedFields(reflect.ValueOf(cfg), "", func(path string, field reflect.Value) {
		ss, _ := field.Interface().(*secrets.SecureString)
		if !ss.IsDestroyed(t.Context()) {
			survivors = append(survivors, path)
		}
	})

	if len(survivors) > 0 {
		t.Errorf("Config.Destroy left %d protected field(s) resident:\n\t%s\n\n"+
			"Add them to the list in Config.Destroy. Every *secrets.SecureString "+
			"reachable from Config must be wiped, or a failed load and a normal "+
			"shutdown both leak it.", len(survivors), strings.Join(survivors, "\n\t"))
	}
}

// TestLoad_ParseFailureDestroysThePostgresURL is the specific regression for
// the field that was missing, exercised through the path that made it matter:
// a DSN carries its credentials inline, so a failed load that leaves it
// resident leaks a database password as surely as leaving the password field
// would.
func TestLoad_ParseFailureDestroysThePostgresURL(t *testing.T) {
	captured := captureDestroy(t)

	// The URL decodes first; the malformed port then fails the decode.
	path := writeConfig(t, `
storage:
  postgres:
    url: "postgres://signal:hunter2@db.example/signal?sslmode=require"
server:
  httpPort: "not-a-number"
`)

	cfg, err := Load(t.Context(), path)
	if err == nil {
		t.Fatal("Load accepted a malformed config")
	}
	if cfg != nil {
		t.Fatal("Load returned a Config alongside an error")
	}

	c := *captured
	if c == nil {
		t.Fatal("a failed parse abandoned the Config it had already built")
	}
	if url := c.Storage.Postgres.URL; url != nil && !url.IsDestroyed(t.Context()) {
		t.Error("storage.postgres.url survived a failed parse — the DSN's embedded credentials are still resident")
	}
}
