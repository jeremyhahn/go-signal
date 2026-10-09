package config

import (
	"net"
	"strconv"
)

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

	// signald's own main listeners.
	KeyServerHTTPListen AddressKey = "server.httpListen"
	KeyServerGRPCListen AddressKey = "server.grpcListen"

	// The remote endpoints signald dials. Empty disables the remote path.
	KeyKeyTransparencyRemoteAddr AddressKey = "keyTransparency.remoteAddr"
	KeyVerificationRemoteAddr    AddressKey = "verification.remoteAddr"
	KeyStorageServiceRemoteURL   AddressKey = "storageService.remoteUrl"
	KeySVR2RemoteURL             AddressKey = "svr2.remoteUrl"

	// The address signald advertises to clients for attachment uploads.
	KeyAttachmentsTusURI AddressKey = "attachments.tusUri"
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
// Config field that carries the resolved value. An optional address has an
// empty default and may be left or set empty: empty disables the listener or
// remote path it names (a gRPC listener, a dialer, an advertised URI).
type addressDefault struct {
	key      AddressKey
	value    string
	field    func(*Config) *string
	optional bool
}

// optionalAddress is the defaults-layer entry for an address that is empty
// unless an operator sets it.
func optionalAddress(key AddressKey, field func(*Config) *string) addressDefault {
	return addressDefault{key: key, field: field, optional: true}
}

// addressDefaults is the defaults layer for bind addresses, applied before
// the config file is decoded so that any key the file sets wins.
var addressDefaults = []addressDefault{
	{KeyHealthListen, DefaultHealthListen, func(c *Config) *string { return &c.Health.Listen }, false},
	{KeyVerificationGRPCListen, DefaultVerificationGRPCListen, func(c *Config) *string { return &c.Verification.GRPCListen }, false},
	{KeySVR2HTTPListen, DefaultSVR2HTTPListen, func(c *Config) *string { return &c.SVR2.HTTPListen }, false},
	{KeySVR2WSListen, DefaultSVR2WSListen, func(c *Config) *string { return &c.SVR2.WSListen }, false},
	{KeyCDSIWSListen, DefaultCDSIWSListen, func(c *Config) *string { return &c.CDSI.WSListen }, false},
	{KeyStorageServiceHTTPListen, DefaultStorageServiceHTTPListen, func(c *Config) *string { return &c.StorageService.HTTPListen }, false},
	{KeyKeyTransparencyGRPCListen, DefaultKeyTransparencyGRPCListen, func(c *Config) *string { return &c.KeyTransparency.GRPCListen }, false},
	optionalAddress(KeyServerHTTPListen, func(c *Config) *string { return &c.Server.HTTPListen }),
	optionalAddress(KeyServerGRPCListen, func(c *Config) *string { return &c.Server.GRPCListen }),
	optionalAddress(KeyKeyTransparencyRemoteAddr, func(c *Config) *string { return &c.KeyTransparency.RemoteAddr }),
	optionalAddress(KeyVerificationRemoteAddr, func(c *Config) *string { return &c.Verification.RemoteAddr }),
	optionalAddress(KeyStorageServiceRemoteURL, func(c *Config) *string { return &c.StorageService.RemoteURL }),
	optionalAddress(KeySVR2RemoteURL, func(c *Config) *string { return &c.SVR2.RemoteURL }),
	optionalAddress(KeyAttachmentsTusURI, func(c *Config) *string { return &c.Attachments.TusURI }),
}

// applyDefaults populates the defaults layer into c.
func applyDefaults(c *Config) {
	for _, d := range addressDefaults {
		*d.field(c) = d.value
	}
}

// resolveServerListeners folds the legacy server.host, server.httpPort and
// server.grpcPort keys into the listen addresses when no layer set the
// address itself. It runs after the file, environment and flag layers, so
// an address set by any of them (flags > env > file) always wins over the
// legacy keys, which are file-layer values. It is idempotent.
func resolveServerListeners(c *Config) {
	for _, l := range []struct {
		listen *string
		port   int
	}{
		{&c.Server.HTTPListen, c.Server.HTTPPort},
		{&c.Server.GRPCListen, c.Server.GRPCPort},
	} {
		if *l.listen == "" && l.port != 0 {
			*l.listen = net.JoinHostPort(c.Server.Host, strconv.Itoa(l.port))
		}
	}
}

// validateAddresses rejects a bind address a file or flag explicitly
// emptied: an empty address would make the listener bind a random port on
// every interface instead of failing closed.
func validateAddresses(c *Config) error {
	for _, d := range addressDefaults {
		if !d.optional && *d.field(c) == "" {
			return &ConfigValidationError{Field: string(d.key), Message: "listen address must not be empty"}
		}
	}
	return nil
}
