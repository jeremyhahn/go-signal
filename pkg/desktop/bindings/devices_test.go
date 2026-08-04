//go:build desktop

package bindings

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// TestNewDeviceBindings verifies construction.
func TestNewDeviceBindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewDeviceBindings(newBindClient(t))
		require.NotNil(t, b)
	})
	t.Run("RetainsClient", func(t *testing.T) {
		c := newBindClient(t)
		b := NewDeviceBindings(c)
		require.NotNil(t, b.client)
	})
}

// TestDeviceBindings_ListDevices tests listing linked devices.
func TestDeviceBindings_ListDevices(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/devices" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"devices": []signal.Device{{ID: 1, Name: "primary"}},
			})
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		devices, err := b.ListDevices()
		require.NoError(t, err)
		assert.Len(t, devices, 1)
		assert.Equal(t, 1, devices[0].ID)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusUnauthorized)
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		_, err := b.ListDevices()
		require.Error(t, err)
	})
}

// TestDeviceBindings_RemoveDevice tests unlinking a device.
func TestDeviceBindings_RemoveDevice(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || !strings.HasPrefix(r.URL.Path, "/v1/devices/") {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		require.NoError(t, b.RemoveDevice(2))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusForbidden)
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		require.Error(t, b.RemoveDevice(99))
	})
}

// TestDeviceBindings_AddDevice tests linking a new device.
func TestDeviceBindings_AddDevice(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/v1/provisioning/") {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		require.NoError(t, b.AddDevice("sgnl://linkdevice?uuid=x&pub_key=y"))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusBadRequest)
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		require.Error(t, b.AddDevice("bad-uri"))
	})
}

// TestDeviceBindings_GenerateProvisioningURI tests QR code URI generation.
func TestDeviceBindings_GenerateProvisioningURI(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/accounts/whoami" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signal.Account{UUID: "my-device-uuid"})
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		uri, err := b.GenerateProvisioningURI()
		require.NoError(t, err)
		assert.Contains(t, uri, "my-device-uuid")
		assert.Contains(t, uri, "sgnl://linkdevice")
	})
	t.Run("WhoAmIError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusUnauthorized)
		}))
		defer srv.Close()

		b := NewDeviceBindings(newBindClientURL(t, srv.URL))
		_, err := b.GenerateProvisioningURI()
		require.Error(t, err)
	})
}
