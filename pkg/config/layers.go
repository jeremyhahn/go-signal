package config

import (
	"strings"
	"unicode"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// EnvPrefix is the product prefix every configuration environment variable
// carries (handbook software/conventions/configuration.md §2).
const EnvPrefix = "SIGNAL"

// EnvName returns the environment variable that sets key: EnvPrefix, "_",
// then the key upper-cased with "." replaced by "_". camelCase is not
// split, so keyTransparency.grpcListen is SIGNAL_KEYTRANSPARENCY_GRPCLISTEN.
func EnvName(key AddressKey) string {
	return EnvPrefix + "_" + strings.ToUpper(strings.ReplaceAll(string(key), ".", "_"))
}

// FlagName returns the command-line flag that sets key: the key path in
// kebab case, so keyTransparency.grpcListen is key-transparency-grpc-listen.
func FlagName(key AddressKey) string {
	var b strings.Builder
	prevSep := true
	for _, r := range string(key) {
		if r == '.' {
			b.WriteByte('-')
			prevSep = true
			continue
		}
		if unicode.IsUpper(r) {
			if !prevSep {
				b.WriteByte('-')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

// newEnvResolver returns the viper instance that resolves the environment
// layer. Its key mapping is the one EnvName documents: viper lower-cases
// the key, applies the replacer, upper-cases the result and prepends the
// prefix.
func newEnvResolver() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix(EnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	return v
}

// applyEnv overlays every address whose environment variable is set and
// non-empty.
func applyEnv(c *Config) {
	v := newEnvResolver()
	for _, d := range addressDefaults {
		if v.IsSet(string(d.key)) {
			*d.field(c) = v.GetString(string(d.key))
		}
	}
}

// AddAddressFlags registers one string flag per key on fs, named by
// FlagName. Each flag's displayed default is the defaults-layer value; it
// only takes effect when the operator sets it (see LoadWithFlags). Passing
// a key that is not an address key panics, as registering a duplicate flag
// does in pflag: both are programming errors caught at start-up.
func AddAddressFlags(fs *pflag.FlagSet, keys ...AddressKey) {
	for _, key := range keys {
		d, ok := lookupAddress(key)
		if !ok {
			panic(&ConfigValidationError{Field: string(key), Message: "not an address key"})
		}
		fs.String(FlagName(key), d.value,
			"listen address ("+string(key)+" in the config file, "+EnvName(key)+" in the environment)")
	}
}

// applyFlags overlays every registered address flag the operator set. A
// flag left at its default never overrides a lower layer.
func applyFlags(c *Config, fs *pflag.FlagSet) {
	if fs == nil {
		return
	}
	for _, d := range addressDefaults {
		if f := fs.Lookup(FlagName(d.key)); f != nil && f.Changed {
			*d.field(c) = f.Value.String()
		}
	}
}

// lookupAddress returns the defaults-layer entry for key.
func lookupAddress(key AddressKey) (addressDefault, bool) {
	for _, d := range addressDefaults {
		if d.key == key {
			return d, true
		}
	}
	return addressDefault{}, false
}

// Address returns the resolved value of key, or "" if key is not an
// address key.
func (c *Config) Address(key AddressKey) string {
	d, ok := lookupAddress(key)
	if !ok {
		return ""
	}
	return *d.field(c)
}
