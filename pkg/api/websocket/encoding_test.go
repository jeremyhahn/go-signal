package websocket

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestMustMarshalBase64_ValidInput(t *testing.T) {
	input := map[string]string{"key": "value"}
	result := mustMarshalBase64(input)
	if result == "" {
		t.Fatal("mustMarshalBase64 returned empty string for valid input")
	}

	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}

	var output map[string]string
	if err := json.Unmarshal(decoded, &output); err != nil {
		t.Fatalf("decoded value is not valid JSON: %v", err)
	}

	if output["key"] != "value" {
		t.Errorf("output[key] = %q, want %q", output["key"], "value")
	}
}

func TestMustMarshalBase64_Struct(t *testing.T) {
	type testStruct struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	input := testStruct{Name: "test", Count: 42}
	result := mustMarshalBase64(input)
	if result == "" {
		t.Fatal("mustMarshalBase64 returned empty string for struct")
	}

	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}

	var output testStruct
	if err := json.Unmarshal(decoded, &output); err != nil {
		t.Fatalf("decoded value is not valid JSON: %v", err)
	}

	if output.Name != "test" {
		t.Errorf("Name = %q, want %q", output.Name, "test")
	}
	if output.Count != 42 {
		t.Errorf("Count = %d, want %d", output.Count, 42)
	}
}

func TestMustMarshalBase64_EmptyMap(t *testing.T) {
	input := map[string]string{}
	result := mustMarshalBase64(input)
	if result == "" {
		t.Fatal("mustMarshalBase64 returned empty string for empty map")
	}

	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}

	if string(decoded) != "{}" {
		t.Errorf("decoded = %q, want %q", string(decoded), "{}")
	}
}

func TestMustMarshalBase64_NilValue(t *testing.T) {
	result := mustMarshalBase64(nil)
	if result == "" {
		t.Fatal("mustMarshalBase64 returned empty string for nil (JSON null)")
	}

	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}

	if string(decoded) != "null" {
		t.Errorf("decoded = %q, want %q", string(decoded), "null")
	}
}

func TestMustMarshalBase64_StringValue(t *testing.T) {
	result := mustMarshalBase64("hello")
	if result == "" {
		t.Fatal("mustMarshalBase64 returned empty string for string input")
	}

	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}

	if string(decoded) != `"hello"` {
		t.Errorf("decoded = %q, want %q", string(decoded), `"hello"`)
	}
}

func TestMustMarshalBase64_UnsupportedType(t *testing.T) {
	// Channels cannot be marshaled to JSON.
	ch := make(chan int)
	result := mustMarshalBase64(ch)
	if result != "" {
		t.Errorf("mustMarshalBase64 returned %q for unsupported type, want empty", result)
	}
}

func TestEncodeBase64_ValidInput(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "simple string",
			input: []byte("hello"),
			want:  base64.StdEncoding.EncodeToString([]byte("hello")),
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02, 0xff},
			want:  base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0xff}),
		},
		{
			name:  "empty input",
			input: []byte{},
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeBase64(tt.input)
			if got != tt.want {
				t.Errorf("encodeBase64() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncodeBase64_NilInput(t *testing.T) {
	result := encodeBase64(nil)
	if result != "" {
		t.Errorf("encodeBase64(nil) = %q, want empty string", result)
	}
}

func TestEncodeBase64_Roundtrip(t *testing.T) {
	original := []byte("roundtrip test data with special chars: !@#$%^&*()")
	encoded := encodeBase64(original)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if string(decoded) != string(original) {
		t.Errorf("roundtrip failed: got %q, want %q", string(decoded), string(original))
	}
}

func TestEncodeBase64_LargeInput(t *testing.T) {
	input := make([]byte, 10000)
	for i := range input {
		input[i] = byte(i % 256)
	}

	encoded := encodeBase64(input)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to decode large input: %v", err)
	}

	if len(decoded) != len(input) {
		t.Errorf("decoded length = %d, want %d", len(decoded), len(input))
	}
}
