package secrets

import (
	"context"
	"reflect"
)

// secureStringType is the reflect.Type for *SecureString, used for fast
// type comparison during struct field processing.
var secureStringType = reflect.TypeOf((*SecureString)(nil))

// ConfigProcessor walks a configuration struct recursively and resolves
// string fields and *SecureString fields that contain secret URIs using
// the provided ResolverRegistry.
type ConfigProcessor struct {
	registry *ResolverRegistry
}

// NewConfigProcessor creates a new ConfigProcessor.
func NewConfigProcessor(registry *ResolverRegistry) *ConfigProcessor {
	return &ConfigProcessor{
		registry: registry,
	}
}

// Process walks the given config struct (must be a pointer to a struct) and
// resolves all string and *SecureString fields that contain registered URI
// schemes. The struct is modified in place.
func (p *ConfigProcessor) Process(ctx context.Context, cfg any) error {
	v := reflect.ValueOf(cfg)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return &ProcessingError{
			Field: "<root>",
			Cause: &InvalidURIError{URI: "", Message: "cfg must be a pointer to a struct"},
		}
	}
	return p.processValue(ctx, v.Elem(), "")
}

// processValue recursively walks a reflect.Value and resolves string and
// *SecureString fields.
func (p *ConfigProcessor) processValue(ctx context.Context, v reflect.Value, path string) error {
	// Check for *SecureString before descending into pointer/struct logic.
	if v.Type() == secureStringType {
		if !v.CanSet() {
			return nil
		}
		return p.resolveSecureStringField(ctx, v, path)
	}

	switch v.Kind() {
	case reflect.Struct:
		return p.processStruct(ctx, v, path)
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return p.processValue(ctx, v.Elem(), path)
	case reflect.String:
		if !v.CanSet() {
			return nil
		}
		return p.resolveStringField(ctx, v, path)
	}
	return nil
}

// processStruct iterates over all fields of a struct and processes each one.
func (p *ConfigProcessor) processStruct(ctx context.Context, v reflect.Value, path string) error {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		fieldPath := path
		if fieldPath != "" {
			fieldPath += "."
		}
		fieldPath += field.Name

		if err := p.processValue(ctx, v.Field(i), fieldPath); err != nil {
			return err
		}
	}
	return nil
}

// resolveStringField resolves a single string field value through the registry.
// On success the field is updated with the plaintext value of the resolved
// SecureString and the SecureString is immediately destroyed.
func (p *ConfigProcessor) resolveStringField(ctx context.Context, v reflect.Value, path string) error {
	original := v.String()
	if original == "" {
		return nil
	}

	resolved, err := p.registry.Resolve(ctx, original)
	if err != nil {
		return &ProcessingError{Field: path, Cause: err}
	}
	defer resolved.Destroy()

	plain := resolved.Plaintext(ctx)
	if plain != original {
		v.SetString(plain)
	}
	return nil
}

// resolveSecureStringField resolves a *SecureString field by reading its
// current plaintext, resolving any URI, and replacing the field value with a
// new SecureString containing the resolved secret.
func (p *ConfigProcessor) resolveSecureStringField(ctx context.Context, v reflect.Value, path string) error {
	// Get the current *SecureString value (may be nil pointer).
	existing, _ := v.Interface().(*SecureString)

	var original string
	if existing != nil {
		original = existing.Plaintext(ctx)
	}
	if original == "" {
		return nil
	}

	resolved, err := p.registry.Resolve(ctx, original)
	if err != nil {
		return &ProcessingError{Field: path, Cause: err}
	}

	// If the value changed, replace the field with the resolved SecureString.
	// Destroy the old value to free protected memory.
	resolvedPlain := resolved.Plaintext(ctx)
	if resolvedPlain != original {
		if existing != nil {
			existing.Destroy()
		}
		v.Set(reflect.ValueOf(resolved))
	} else {
		// No change — destroy the temporary resolved copy.
		resolved.Destroy()
	}
	return nil
}
