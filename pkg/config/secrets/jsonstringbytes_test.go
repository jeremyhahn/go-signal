package secrets

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type jsonStringBytesHolder struct {
	Password JSONStringBytes `json:"password"`
}

// A string field rejected every wrong-typed occurrence of its key, wherever it
// sat among duplicates, with *json.UnmarshalTypeError. JSONStringBytes stands
// in for that field, so it must reject the same payloads the same way.
func TestJSONStringBytes_RejectsWrongTypedOccurrences(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		kind string
	}{
		"number":                 {`{"password":123}`, "number"},
		"negative number":        {`{"password":-1}`, "number"},
		"bool true":              {`{"password":true}`, "bool"},
		"bool false":             {`{"password":false}`, "bool"},
		"object":                 {`{"password":{"a":"b"}}`, "object"},
		"array":                  {`{"password":["a"]}`, "array"},
		"wrong-typed then valid": {`{"password":123,"password":"ok"}`, "number"},
		"valid then wrong-typed": {`{"password":"ok","password":[1]}`, "array"},
		"null then wrong-typed":  {`{"password":null,"password":false}`, "bool"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdlib struct {
				Password string `json:"password"`
			}
			if err := json.Unmarshal([]byte(tc.body), &stdlib); err == nil {
				t.Fatalf("precondition: a string field accepted %s", tc.body)
			}

			var h jsonStringBytesHolder
			defer h.Password.Wipe()
			err := json.Unmarshal([]byte(tc.body), &h)
			var typeErr *json.UnmarshalTypeError
			if !errors.As(err, &typeErr) {
				t.Fatalf("error = %v, want *json.UnmarshalTypeError", err)
			}
			if typeErr.Value != tc.kind {
				t.Errorf("Value = %q, want %q", typeErr.Value, tc.kind)
			}
			if typeErr.Type.Kind() != reflect.String {
				t.Errorf("Type = %v, want string", typeErr.Type)
			}
		})
	}
}

// Valid payloads decode exactly as a string field would: the last string
// occurrence wins, and null leaves the earlier value in place.
func TestJSONStringBytes_DecodesLikeAStringField(t *testing.T) {
	for name, body := range map[string]string{
		"single":                `{"password":"pw"}`,
		"escaped":               `{"password":"a\"b\\cé"}`,
		"duplicate strings":     `{"password":"first","password":"second"}`,
		"string then null":      `{"password":"kept","password":null}`,
		"null":                  `{"password":null}`,
		"empty":                 `{"password":""}`,
		"absent":                `{}`,
		"invalid UTF-8 coerced": "{\"password\":\"a\xffb\"}",
	} {
		t.Run(name, func(t *testing.T) {
			var stdlib struct {
				Password string `json:"password"`
			}
			if err := json.Unmarshal([]byte(body), &stdlib); err != nil {
				t.Fatalf("precondition: a string field rejected %s: %v", body, err)
			}

			var h jsonStringBytesHolder
			defer h.Password.Wipe()
			if err := json.Unmarshal([]byte(body), &h); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got := string(h.Password.Bytes()); got != stdlib.Password {
				t.Errorf("decoded %q, string field decoded %q", got, stdlib.Password)
			}
		})
	}
}

// Replacing an earlier occurrence must wipe its bytes, not abandon them.
func TestJSONStringBytes_WipesTheOccurrenceItReplaces(t *testing.T) {
	var j JSONStringBytes
	defer j.Wipe()
	if err := j.UnmarshalJSON([]byte(`"first"`)); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := j.Bytes()
	if err := j.UnmarshalJSON([]byte(`"second"`)); err != nil {
		t.Fatalf("second: %v", err)
	}
	for i, c := range first {
		if c != 0 {
			t.Fatalf("replaced bytes not wiped at %d: % x", i, first)
		}
	}
	if got := string(j.Bytes()); got != "second" {
		t.Errorf("Bytes = %q, want second", got)
	}
}

// A rejected occurrence must leave the earlier value untouched so the caller's
// deferred Wipe still reaches it.
func TestJSONStringBytes_FailedOccurrenceKeepsEarlierBytes(t *testing.T) {
	var j JSONStringBytes
	defer j.Wipe()
	if err := j.UnmarshalJSON([]byte(`"kept"`)); err != nil {
		t.Fatalf("first: %v", err)
	}
	for name, data := range map[string]string{
		"wrong type":         `42`,
		"empty":              ``,
		"malformed string":   `"bad\escape"`,
		"unterminated":       `"open`,
		"raw control in str": "\"a\x01b\"",
	} {
		t.Run(name, func(t *testing.T) {
			if err := j.UnmarshalJSON([]byte(data)); err == nil {
				t.Fatalf("expected %q to be rejected", data)
			}
			if got := string(j.Bytes()); got != "kept" {
				t.Errorf("Bytes = %q, want kept", got)
			}
		})
	}
}

func TestJSONStringBytes_WipeZeroesAndIsIdempotent(t *testing.T) {
	var j JSONStringBytes
	j.Wipe() // zero value

	if err := j.UnmarshalJSON([]byte(`"secret"`)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	b := j.Bytes()
	j.Wipe()
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d not wiped: % x", i, b)
		}
	}
	if j.Bytes() != nil {
		t.Error("Bytes after Wipe must be nil")
	}
	j.Wipe()
}

func TestFirstByte(t *testing.T) {
	if got := firstByte(nil); got != 0 {
		t.Errorf("firstByte(nil) = %q, want 0", got)
	}
	if got := firstByte([]byte("xy")); got != 'x' {
		t.Errorf("firstByte(xy) = %q, want x", got)
	}
}
