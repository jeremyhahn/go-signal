package config

// HealthConfig configures the standalone health/metrics sidecar that the
// gRPC-native binaries (registration-service, key-transparency, signald)
// run for kubelet probes and Prometheus scrape.
type HealthConfig struct {
	// Listen is the host:port the sidecar binds /healthz, /readyz and
	// /metrics to. Defaults to DefaultHealthListen.
	Listen string `yaml:"listen"`
}

// AddressKey is the dotted YAML path of a bind address. It is also the key
// the environment and flag layers resolve (see the package doc for the
// naming rules).
type AddressKey string

// The address keys, one per listener.
const (
	KeyHealthListen              AddressKey = "health.listen"
	KeyVerificationGRPCListen    AddressKey = "verification.grpcListen"
	KeySVR2HTTPListen            AddressKey = "svr2.httpListen"
	KeySVR2WSListen              AddressKey = "svr2.wsListen"
	KeyCDSIWSListen              AddressKey = "cdsi.wsListen"
	KeyStorageServiceHTTPListen  AddressKey = "storageService.httpListen"
	KeyKeyTransparencyGRPCListen AddressKey = "keyTransparency.grpcListen"
)

// The defaults layer for every bind address. These are the only places a
// listen literal may appear in non-test code (handbook
// software/conventions/configuration.md §3): each is the documented
// default that the config file, environment and flag override.
const (
	DefaultHealthListen              = "0.0.0.0:8099"
	DefaultVerificationGRPCListen    = "0.0.0.0:8090"
	DefaultSVR2HTTPListen            = "0.0.0.0:8091"
	DefaultSVR2WSListen              = "0.0.0.0:8092"
	DefaultCDSIWSListen              = "0.0.0.0:8094"
	DefaultStorageServiceHTTPListen  = "0.0.0.0:8096"
	DefaultKeyTransparencyGRPCListen = "0.0.0.0:8098"
)

// addressDefault binds one address key to its default value and to the
// Config field that carries the resolved value.
type addressDefault struct {
	key   AddressKey
	value string
	field func(*Config) *string
}

// addressDefaults is the defaults layer for bind addresses, applied before
// the config file is decoded so that any key the file sets wins.
var addressDefaults = []addressDefault{
	{KeyHealthListen, DefaultHealthListen, func(c *Config) *string { return &c.Health.Listen }},
	{KeyVerificationGRPCListen, DefaultVerificationGRPCListen, func(c *Config) *string { return &c.Verification.GRPCListen }},
	{KeySVR2HTTPListen, DefaultSVR2HTTPListen, func(c *Config) *string { return &c.SVR2.HTTPListen }},
	{KeySVR2WSListen, DefaultSVR2WSListen, func(c *Config) *string { return &c.SVR2.WSListen }},
	{KeyCDSIWSListen, DefaultCDSIWSListen, func(c *Config) *string { return &c.CDSI.WSListen }},
	{KeyStorageServiceHTTPListen, DefaultStorageServiceHTTPListen, func(c *Config) *string { return &c.StorageService.HTTPListen }},
	{KeyKeyTransparencyGRPCListen, DefaultKeyTransparencyGRPCListen, func(c *Config) *string { return &c.KeyTransparency.GRPCListen }},
}

// applyDefaults populates the defaults layer into c.
func applyDefaults(c *Config) {
	for _, d := range addressDefaults {
		*d.field(c) = d.value
	}
}

// validateAddresses rejects a bind address a file or flag explicitly
// emptied: an empty address would make the listener bind a random port on
// every interface instead of failing closed.
func validateAddresses(c *Config) error {
	for _, d := range addressDefaults {
		if *d.field(c) == "" {
			return &ConfigValidationError{Field: string(d.key), Message: "listen address must not be empty"}
		}
	}
	return nil
}
