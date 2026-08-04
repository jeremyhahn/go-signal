package accounts

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/auth"
)

// mustSaltedTokenHash creates a SaltedTokenHash for test fixtures.
// It panics on error, which is acceptable in test initialization.
func mustSaltedTokenHash(token string) *auth.SaltedTokenHash {
	h, err := auth.NewSaltedTokenHash(token)
	if err != nil {
		panic("mustSaltedTokenHash: " + err.Error())
	}
	return h
}

func TestPrimaryDeviceIDConstant(t *testing.T) {
	if PrimaryDeviceID != 1 {
		t.Errorf("PrimaryDeviceID = %d, want 1", PrimaryDeviceID)
	}
}

func TestDefaultMaxDevicesConstant(t *testing.T) {
	if DefaultMaxDevices != 6 {
		t.Errorf("DefaultMaxDevices = %d, want 6", DefaultMaxDevices)
	}
}

func TestAccount_GetDevice(t *testing.T) {
	tests := []struct {
		name     string
		devices  []Device
		id       uint64
		wantNil  bool
		wantName string
	}{
		{
			name: "find primary device",
			devices: []Device{
				{ID: 1, Name: "primary"},
				{ID: 2, Name: "secondary"},
			},
			id:       1,
			wantName: "primary",
		},
		{
			name: "find secondary device",
			devices: []Device{
				{ID: 1, Name: "primary"},
				{ID: 2, Name: "secondary"},
				{ID: 3, Name: "tablet"},
			},
			id:       3,
			wantName: "tablet",
		},
		{
			name: "device not found",
			devices: []Device{
				{ID: 1, Name: "primary"},
			},
			id:      99,
			wantNil: true,
		},
		{
			name:    "empty device list",
			devices: nil,
			id:      1,
			wantNil: true,
		},
		{
			name:    "zero id lookup",
			devices: []Device{{ID: 1}},
			id:      0,
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Account{Devices: tt.devices}
			got := a.GetDevice(tt.id)
			if tt.wantNil {
				if got != nil {
					t.Errorf("GetDevice(%d) = %+v, want nil", tt.id, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("GetDevice(%d) = nil, want device with name %q", tt.id, tt.wantName)
				return
			}
			if got.Name != tt.wantName {
				t.Errorf("GetDevice(%d).Name = %q, want %q", tt.id, got.Name, tt.wantName)
			}
		})
	}
}

func TestAccount_GetDevice_ReturnsPointerToSliceElement(t *testing.T) {
	a := &Account{
		Devices: []Device{
			{ID: 1, Name: "original"},
		},
	}
	d := a.GetDevice(1)
	if d == nil {
		t.Fatal("GetDevice(1) = nil")
		return
	}
	d.Name = "modified"
	if a.Devices[0].Name != "modified" {
		t.Error("modifying returned device did not modify the slice element")
	}
}

func TestAccount_PrimaryDevice(t *testing.T) {
	tests := []struct {
		name    string
		devices []Device
		wantNil bool
	}{
		{
			name:    "has primary",
			devices: []Device{{ID: 1, Name: "phone"}},
		},
		{
			name:    "no primary",
			devices: []Device{{ID: 2, Name: "tablet"}},
			wantNil: true,
		},
		{
			name:    "empty devices",
			devices: nil,
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Account{Devices: tt.devices}
			got := a.PrimaryDevice()
			if tt.wantNil && got != nil {
				t.Errorf("PrimaryDevice() = %+v, want nil", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("PrimaryDevice() = nil, want non-nil")
			}
		})
	}
}

func TestAccount_IsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		devices []Device
		want    bool
	}{
		{
			name: "one enabled device",
			devices: []Device{
				{
					ID:            1,
					AuthTokenHash: mustSaltedTokenHash("tok"),
					SignedPreKey:  &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
				},
			},
			want: true,
		},
		{
			name: "no devices",
			want: false,
		},
		{
			name: "all disabled - no auth token hash",
			devices: []Device{
				{ID: 1, SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")}},
			},
			want: false,
		},
		{
			name: "all disabled - no signed pre key",
			devices: []Device{
				{ID: 1, AuthTokenHash: mustSaltedTokenHash("tok")},
			},
			want: false,
		},
		{
			name: "mixed enabled and disabled",
			devices: []Device{
				{ID: 1},
				{
					ID:            2,
					AuthTokenHash: mustSaltedTokenHash("tok"),
					SignedPreKey:  &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Account{Devices: tt.devices}
			got := a.IsEnabled()
			if got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDeviceEnabled(t *testing.T) {
	tests := []struct {
		name   string
		device *Device
		want   bool
	}{
		{
			name:   "enabled - has auth token hash and signed pre key",
			device: &Device{AuthTokenHash: mustSaltedTokenHash("tok"), SignedPreKey: &SignedPreKey{PublicKey: []byte("k")}},
			want:   true,
		},
		{
			name:   "disabled - missing auth token hash",
			device: &Device{AuthTokenHash: nil, SignedPreKey: &SignedPreKey{PublicKey: []byte("k")}},
			want:   false,
		},
		{
			name:   "disabled - missing signed pre key",
			device: &Device{AuthTokenHash: mustSaltedTokenHash("tok"), SignedPreKey: nil},
			want:   false,
		},
		{
			name:   "disabled - both missing",
			device: &Device{},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDeviceEnabled(tt.device)
			if got != tt.want {
				t.Errorf("IsDeviceEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccount_ZeroValue(t *testing.T) {
	var a Account
	if a.UUID != "" {
		t.Error("zero Account.UUID should be empty")
	}
	if a.Version != 0 {
		t.Error("zero Account.Version should be 0")
	}
	if !a.CreatedAt.IsZero() {
		t.Error("zero Account.CreatedAt should be zero time")
	}
	if a.GetDevice(1) != nil {
		t.Error("zero Account.GetDevice(1) should be nil")
	}
	if a.PrimaryDevice() != nil {
		t.Error("zero Account.PrimaryDevice() should be nil")
	}
	if a.IsEnabled() {
		t.Error("zero Account.IsEnabled() should be false")
	}
}

func TestDevice_ZeroValue(t *testing.T) {
	var d Device
	if d.ID != 0 {
		t.Error("zero Device.ID should be 0")
	}
	if !d.CreatedAt.IsZero() {
		t.Error("zero Device.CreatedAt should be zero time")
	}
	if IsDeviceEnabled(&d) {
		t.Error("IsDeviceEnabled on zero Device should be false")
	}
}

func TestSignedPreKey_Fields(t *testing.T) {
	spk := &SignedPreKey{
		KeyID:     42,
		PublicKey: []byte("pub-key-data"),
		Signature: []byte("sig-data"),
	}
	if spk.KeyID != 42 {
		t.Errorf("KeyID = %d, want 42", spk.KeyID)
	}
	if string(spk.PublicKey) != "pub-key-data" {
		t.Errorf("PublicKey = %q, want %q", spk.PublicKey, "pub-key-data")
	}
	if string(spk.Signature) != "sig-data" {
		t.Errorf("Signature = %q, want %q", spk.Signature, "sig-data")
	}
}

func TestKyberPreKey_Fields(t *testing.T) {
	kpk := &KyberPreKey{
		KeyID:     99,
		PublicKey: []byte("kyber-pub"),
		Signature: []byte("kyber-sig"),
	}
	if kpk.KeyID != 99 {
		t.Errorf("KeyID = %d, want 99", kpk.KeyID)
	}
	if string(kpk.PublicKey) != "kyber-pub" {
		t.Errorf("PublicKey = %q, want %q", kpk.PublicKey, "kyber-pub")
	}
}

func TestDataReport_Fields(t *testing.T) {
	dr := &DataReport{
		UUID:    "test-uuid",
		Number:  "+15551234567",
		Devices: []uint64{1, 2, 3},
	}
	if dr.UUID != "test-uuid" {
		t.Errorf("UUID = %q, want %q", dr.UUID, "test-uuid")
	}
	if dr.Number != "+15551234567" {
		t.Errorf("Number = %q, want %q", dr.Number, "+15551234567")
	}
	if len(dr.Devices) != 3 {
		t.Errorf("len(Devices) = %d, want 3", len(dr.Devices))
	}
}

func TestDeviceCapabilities_Fields(t *testing.T) {
	caps := DeviceCapabilities{
		Storage:                  true,
		Transfer:                 true,
		PaymentActivation:        false,
		DeleteSync:               true,
		VersionedExpirationTimer: false,
	}
	if !caps.Storage {
		t.Error("Storage should be true")
	}
	if !caps.Transfer {
		t.Error("Transfer should be true")
	}
	if caps.PaymentActivation {
		t.Error("PaymentActivation should be false")
	}
}

func TestCreateAccountRequest_Fields(t *testing.T) {
	req := CreateAccountRequest{
		Number:                         "+15551234567",
		IdentityKey:                    []byte("identity"),
		PhoneNumberIdentityKey:         []byte("pni"),
		AuthToken:                      "auth-token",
		RegistrationLock:               "pin",
		UnidentifiedAccessKey:          []byte("uak"),
		UnrestrictedUnidentifiedAccess: true,
		DiscoverableByPhoneNumber:      true,
	}
	if req.Number != "+15551234567" {
		t.Errorf("Number = %q, want %q", req.Number, "+15551234567")
	}
	if !req.UnrestrictedUnidentifiedAccess {
		t.Error("UnrestrictedUnidentifiedAccess should be true")
	}
	if !req.DiscoverableByPhoneNumber {
		t.Error("DiscoverableByPhoneNumber should be true")
	}
}

func TestCreateAccountRequest_ZeroValue(t *testing.T) {
	var req CreateAccountRequest
	if req.Number != "" {
		t.Error("zero CreateAccountRequest.Number should be empty")
	}
	if req.IdentityKey != nil {
		t.Error("zero CreateAccountRequest.IdentityKey should be nil")
	}
	if req.UnrestrictedUnidentifiedAccess {
		t.Error("zero CreateAccountRequest.UnrestrictedUnidentifiedAccess should be false")
	}
}

func TestDevice_TimestampFields(t *testing.T) {
	now := time.Now().UTC()
	d := Device{
		ID:        1,
		CreatedAt: now,
		LastSeen:  now,
	}
	if !d.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", d.CreatedAt, now)
	}
	if !d.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", d.LastSeen, now)
	}
}
